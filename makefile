CC=g++
CFLAGS=-std=c++17 -Wall

all:
	$(CC) $(CFLAGS) isa_netgen.cpp udp_export.cpp -lpcap -ggdb3 -o flow
clean:
	rm -f *.o flow