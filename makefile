CC = gcc
CFLAGS = -std=gnu99 -masm=intel -march=native -mtune=native \
		 -ffreestanding -fno-builtin -nostdlib -nolibc \
		 -fno-stack-protector -fno-pie -no-pie -fomit-frame-pointer
ERRFLAGS = -Wall -Werror
SRC = wol.c
OUT = wol

all:
	$(CC) $(SRC) $(CFLAGS) $(ERRFLAGS) -O1 -o $(OUT)
debug:
	$(CC) $(SRC) $(CFLAGS) -O0 -o $(OUT) -g
release:
	$(CC) $(SRC) $(CFLAGS) $(ERRFLAGS) -O2 -o $(OUT)
clean:
	rm -f $(SRC)