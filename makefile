CC=g++
CFLAGS=-std=c++17 -Wall

all:
	$(CC) $(CFLAGS) isa_netgen.cpp udp_export.cpp -lpcap -ggdb3 -o  isa_netgen
clean:
	rm -f *.o  isa_netgen