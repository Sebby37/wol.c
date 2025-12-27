all:
	gcc -ffreestanding -fno-builtin -std=gnu99 -masm=intel -O0 wol.c -o wol
debug:
	gcc -ffreestanding -fno-builtin -std=gnu99 -masm=intel -O0 wol.c -o wol -g
clean:
	rm -f wol