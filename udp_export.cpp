/*

 Simple echo connected UDP client with two parameters and the connect() function

 Usage: echo-udp-client2 <server IP address/domain name> <port number>

 (c) Petr Matousek, 2016

 Last update: Sept 2019

*/

#include "isa_netgen.h"

#include<cstdio>
#include<cstdlib>
#include<cstring>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<unistd.h>
#include<netdb.h>
#include<err.h>

#define BUFFER 1024                // buffer length

void prepare_export(NETFLOW_FLOW *flow, NETFLOW_HEADER *header) {
    header->flow_sequnce = htonl(header->flow_sequnce);
    flow->dPkts = htonl(flow->dPkts);
    flow->dOctets = htonl(flow->dOctets);
    flow->First = htonl(flow->First);
    flow->Last = htonl(flow->Last);
    flow->srcport = htons(flow->srcport);
    flow->dstport = htons(flow->dstport);
}

void udp_export(NETFLOW_FLOW flow, NETFLOW_HEADER header)
{
    int sock;                        // socket descriptor
    int msg_size, i;
    struct sockaddr_in server; // address structures of the server and the client
    struct hostent *servent;         // network host entry required by gethostbyname()
    char buffer[1024];
    const char *addr = args.netflow_collector;
    const char *port = args.port;
    memset(&server,0,sizeof(server)); // erase the server structure
    server.sin_family = AF_INET;


    printf("%d", header.unix_secs);
    prepare_export(&flow, &header);

    memcpy(buffer, &header, sizeof(header));
    memcpy(buffer + sizeof(header), &flow, sizeof(flow));

    // make DNS resolution of the first parameter using gethostbyname()
    if ((servent = gethostbyname(addr)) == nullptr) // check the first parameter
        errx(1,"gethostbyname() failed\n");

    // copy the first parameter to the server.sin_addr structure
    memcpy(&server.sin_addr,servent->h_addr,servent->h_length);

    char *endptr;
    server.sin_port = htons(strtol(port, &endptr, 10));        // server port (network byte order)

    if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1)   //create a client socket
        err(1,"socket() failed\n");

    printf("* Server socket created\n");

    msg_size = sizeof(header) + sizeof(flow);


    printf("* Creating a connected UDP socket using connect()\n");
    // create a connected UDP socket
    if (connect(sock, (struct sockaddr *)&server, sizeof(server))  == -1)
        err(1, "connect() failed");

    i = send(sock,buffer,msg_size,0);     // send data to the server
    if (i == -1)                   // check if data was sent correctly
        err(1,"send() failed");
    else if (i != msg_size)
        err(1,"send(): buffer written partially");

    close(sock);
    printf("* Closing the client socket ...\n");
}
