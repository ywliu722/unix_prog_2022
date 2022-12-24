CC = gcc
ASM64 = yasm -f elf64 -DYASM -D__x86_64__ -DPIC

CFLAGS	= -g -Wall -masm=intel -fno-stack-protector

PROGS = libmini.so

all: $(PROGS)

libmini.a: libmini64.asm libmini.c
	$(CC) -c $(CFLAGS) -fPIC -nostdlib libmini.c
	$(ASM64) $< -o libmini64.o
	ar rc libmini.a libmini64.o libmini.o

libmini.so: libmini.a
	ld -shared libmini64.o libmini.o -o libmini.so

start.o: start.asm
	$(ASM64) $< -o start.o

write1: start.o write1.c
	$(CC) -c $(CFLAGS) -nostdlib -I. -I.. -DUSEMINI write1.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o write1 write1.o start.o -L. -L.. -lmini
	rm write1.o

alarm1: start.o alarm1.c
	$(CC) -c $(CFLAGS) -nostdlib -I. -I.. -DUSEMINI alarm1.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o alarm1 alarm1.o start.o -L. -L.. -lmini
	rm alarm1.o

alarm2: start.o alarm2.c
	$(CC) -c $(CFLAGS) -nostdlib -I. -I.. -DUSEMINI alarm2.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o alarm2 alarm2.o start.o -L. -L.. -lmini
	rm alarm2.o

alarm3: start.o alarm3.c
	$(CC) -c $(CFLAGS) -nostdlib -I. -I.. -DUSEMINI alarm3.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o alarm3 alarm3.o start.o -L. -L.. -lmini
	rm alarm3.o

jmp1: start.o jmp1.c
	$(CC) -c $(CFLAGS) -nostdlib -I. -I.. -DUSEMINI jmp1.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o jmp1 jmp1.o start.o -L. -L.. -lmini
	rm jmp1.o

clean:
	rm -f *.s *.o *.a *.so write1 alarm1 alarm2 alarm3 jmp1