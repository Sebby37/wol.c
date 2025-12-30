CC = gcc
CFLAGS = -std=gnu99 -masm=intel -march=native -mtune=native \
		 -ffreestanding -fno-builtin -nostdlib -nolibc \
		 -fno-stack-protector -fomit-frame-pointer
SRC = wol.c
OUT = wol

all:
	$(CC) $(SRC) $(CFLAGS) -O1 -o $(OUT)
debug:
	$(CC) $(SRC) $(CFLAGS) -O0 -o $(OUT) -g
release:
	$(CC) $(SRC) $(CFLAGS) -O2 -o $(OUT) -wl,-s
clean:
	rm -f $(SRC)