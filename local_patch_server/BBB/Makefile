all: local_patch_server.c
	rm -f local_patch_server
	arm-linux-gnueabihf-gcc -g -Wall -lm -static -o bbb_local_patch_server local_patch_server.c -lm
	scp bbb_local_patch_server debian@192.168.7.2:/home/debian/

clean:
	rm -f local_patch_server
