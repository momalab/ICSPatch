import networkx as nx
import matplotlib.pyplot as plt
from networkx.generators import directed
from utils.constants import *

class Graph:
    def __init__(self):
        self.graph = nx.DiGraph(directed=True)
        self.regState = {}
        for _regName in ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'ip', 'sp', 'lr']:
            self.regState[_regName] = 0

    def if_node_exists(self, _node_label):
        if _node_label in self.graph.nodes():
            return True
        return False

    def add_regstate_if_new(self, _operand):
        if not _operand in self.regState:
            self.regState[_operand] = 0

    def get_reg_state_value(self, _regName):
        return self.regState[_regName]

    def get_node_attr(self, _node):
        return self.graph.nodes[_node]

    def get_edge_attr(self, _node1, _node2):
        return self.graph.edge[_node1][_node2]

    def get_nodes(self):
        return self.graph.nodes()

    def get_edges(self):
        return self.graph.edges()

    def draw_graph(self):
        memory_nodes = [n for (n, node_type) in nx.get_node_attributes(self.graph, 'node_type').items() if node_type == MEMORY_NODE]
        instruction_nodes = [n for (n, node_type) in nx.get_node_attributes(self.graph, 'node_type').items() if node_type == INSTRUCTION_NODE]

        fig, ax = plt.subplots()
        positions = nx.spring_layout(self.graph, k=0.9, iterations=70)
        nx.draw_networkx_nodes(self.graph, pos=positions, nodelist=memory_nodes, node_color='b', node_size=1050, alpha=0.3)
        nx.draw_networkx_nodes(self.graph, pos=positions, nodelist=instruction_nodes, node_color='r', node_size=1050, alpha=0.3)
        nx.draw_networkx_labels(self.graph, pos=positions, font_size=6, font_family='sans-serif')
        nx.draw_networkx_edge_labels(self.graph, pos=positions, edge_labels=nx.get_edge_attributes(self.graph, 'operation'), font_size=6)
        nx.draw_networkx_edges(self.graph, pos=positions, width=1)
        ax.axis('off')
        plt.show()

    # ICSPatch sepecific functions
    def add_transition_node(self, _instructionAddress, _operand1, _operand2, _operationType, _debug = False):
        self.add_regstate_if_new(_operand1)
        self.add_regstate_if_new(_operand2)

        self.graph.add_node(hex(_instructionAddress), node_type = TRANSITION_NODE, operation_type = _operationType, operand1 = _operand1, operand2 = _operand2)
        self.graph.add_edge(hex(self.regState[_operand2]), hex(_instructionAddress), operation = 'next')
        self.regState[_operand1] = _instructionAddress

        if _debug:
            print("TRANSITION ", hex(_instructionAddress), ": ", _operand1, " ", _operand2)
            print("TRANSITION EDGE ", hex(self.regState[_operand2]), " -> ", hex(_instructionAddress), "[NEXT]")
            print(self.regState)

    def add_memory_node(self, _mem_location_address, _value):
        # Risky addition, delete if needed
        if _mem_location_address == 0:
            return 

        if not self.if_node_exists(hex(_mem_location_address)):
            self.graph.add_node(hex(_mem_location_address), node_type = MEMORY_NODE, value = [hex(_value)])
        elif not hex(_value) in self.graph.nodes[hex(_mem_location_address)]['value']:
            self.graph.nodes[hex(_mem_location_address)]['value'].append(hex(_value))

    def add_load_node(self, _instructionAddress, _operand1, _operand2, _mem_read_address, _mem_value, _debug = False):
        self.add_regstate_if_new(_operand1)
        self.add_regstate_if_new(_operand2)

        self.regState[_operand1] = _instructionAddress

        # Create instruction and mem_read node and connect them
        self.graph.add_node(hex(_instructionAddress), node_type = INSTRUCTION_NODE, operation_type = LDR_INSTRUCTION, operand1 = _operand1)
        self.add_memory_node(_mem_read_address, _mem_value)
        self.graph.add_edge(hex(_mem_read_address), hex(_instructionAddress), operation = 'loads')

        if _debug:
            print("LOAD NODE ", hex(_instructionAddress), ": ", _operand1)
            print("MEMORY NODE ", hex(_mem_read_address))
            print("LOAD EDGE ", hex(_mem_read_address), " -> ", hex(_instructionAddress), "[LOADS]")
            print(self.regState)

        # Handle consecutive loads, Ex:
        # 0x80582bd:	ldr	r3, [r7, #0x14]
        # 0x80582bf:	ldr	r2, [r3]
        # 0x80582c1:	ldr	r3, [r7, #0x10]
        # 0x80582c3:	str	r2, [r3]
        if _operand2 != "r7" and _operand2 != "pc" and not _operand2 is None:
            self.graph.add_edge(hex(self.regState[_operand2]), hex(_instructionAddress), operation = 'next')

            if _debug:
                print("LOAD EDGE ", hex(self.regState[_operand2]), " -> ", hex(_instructionAddress), "[NEXT]")

    def add_store_node(self, _instructionAddress, _operand1, _mem_write_address, _mem_value, _debug = False):
        self.add_regstate_if_new(_operand1)

        # Create instruction and mem_write node and connect them
        self.add_memory_node(_mem_write_address, _mem_value)
        self.graph.add_node(hex(_instructionAddress), node_type = INSTRUCTION_NODE, operation_type = STR_INSTRUCTION, operand1 = _operand1)
        self.graph.add_edge(hex(_instructionAddress), hex(_mem_write_address), operation = 'stores')

        if _debug:
            print("STORE NODE ", hex(_mem_write_address), _mem_value)
            print("STORE NODE ", hex(_instructionAddress), ": ", _operand1)
            print("LOAD EDGE ", hex(_instructionAddress), " -> ", hex(_mem_write_address), "[STORES]")
            print("LOAD EDGE ", hex(self.regState[_operand1]), " -> ", hex(_instructionAddress), "[NEXT]")

        # Create an edgge from the previous transition instruction
        self.graph.add_edge(hex(self.regState[_operand1]), hex(_instructionAddress), operation = 'next')
