all:
	gcc -ffreestanding -fno-builtin -std=gnu99 wol.c -o wol
clean:
	rm -f wol