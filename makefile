CC=g++
CFLAGS=-std=c++17 -Wall

all:
	$(CC) $(CFLAGS) isa_netgen.cpp -lpcap -o isa_netgen
clean:
	rm -f *.o  isa_netgen