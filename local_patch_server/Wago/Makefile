all: local_patch_server.c
	rm -f wago_local_patch_server
	arm-linux-gnueabihf-gcc -g -Wall -lm -static -o wago_local_patch_server local_patch_server.c -lm
	cp wago_local_patch_server /media/sf_Shared-Folder/wago_local_patch_server

clean:
	rm -f wago_local_patch_server
