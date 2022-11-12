Offline NetFlow exportér

Autor: Daniel Chudý, xchudy06
Dátum: 12.11.2022

NetFlow exportér, ktorý zo zachytených sieťových dát vo formáte pcap vytvorí záznamy NetFlow, ktoré odošle na kolektor.

Použitie:
    ./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]
    -f <file> meno analyzovaného súboru alebo STDIN
    -c <neflow_collector:port> IP adresa, alebo hostname NetFlow kolektora. Voliteľne aj UDP 
    port (127.0.0.1:2055, pokiaľ nie je špecifikované)
    -a <active_timer> - interval v sekundách, po ktorom sa exportujú aktívne záznamy na 
    kolektor (60, pokiaľ nie je špecifikované)
    -i <seconds> - interval v sekundách, po ktorého vypršaní sa exportujú neaktívne záznamy na 
    kolektor (10, pokiaľ nie je špecifikované)
    -m <count> - veľkosť flow-cache. Pri dosiahnutí max. veľkosti dôjde k exportu najstaršieho 
    záznamu v cachi na kolektor (1024, pokiaľ nie je špecifikované)

Príklady použitia:
	./flow -f input.pcap -i 15 -a 10            - obmedzenie časovačov
	./flow -m 100                               - obmedzenie veľkosti flow-cache na 100 prvkov, čítanie zo STDIN
	./flow -f input.pcap -c 192.168.0.1:2055    - IP adresa a UDP port kolektora

Súbory:
    isa_netgen.cpp
    isa_netgen.h
	udp_export.cpp
	manual.pdf
	README
	flow.1
    makefile
