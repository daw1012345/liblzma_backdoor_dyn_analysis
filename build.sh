gcc main.c backdoor.o -Wl,-z,now -fno-omit-frame-pointer -g -fPIC -DPIC -fno-lto -ffunction-sections -fdata-sections -o backdoored_file
