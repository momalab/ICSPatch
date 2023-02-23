def hex_str_to_bit_str(hex_str):
    bit_str = ''
    for hex_char in hex_str:
        bit_str += bin(int(hex_char, 16))[2:].zfill(4)

    return bit_str