//    Original owner/creator of this file: Petr Matoušek, VUT FIT BRNO, ISA course
//
//    Simple echo connected UDP client with two parameters and the connect() function
//
//    Usage: echo-udp-client2 <server IP address/domain name> <port number>
//
//    (c) Petr Matousek, 2016
//
//    Last update: Sept 2019

//    Remix by: Daniel Chudý, xchudy06, VUT FIT BRNO, ISA course
//    Date: 07.11.2022

#include "isa_netgen.h"



#define BUFFER 1024    // buffer length

/**
 * @brief prepares the netflow structure (header and flow)
 *
 * @param flow netflow flow structure
 * @param header netflow header structure
 * @return void
*/
void prepare_export(NETFLOW_FLOW *flow, NETFLOW_HEADER *header) {
    header->flow_sequnce = htonl(header->flow_sequnce);
    flow->dPkts = htonl(flow->dPkts);
    flow->dOctets = htonl(flow->dOctets);
    flow->First = htonl(flow->First);
    flow->Last = htonl(flow->Last);
    flow->srcport = htons(flow->srcport);
    flow->dstport = htons(flow->dstport);
}

/**
 * @brief sends the netflow data to the collector
 *
 * @param flow netflow flow structure
 * @param header netflow header structure
 * @return void
*/
void udp_export(NETFLOW_FLOW flow, NETFLOW_HEADER header)
{
    int sock;                   // socket descriptor
    int msg_size, i;
    struct sockaddr_in server;  // address structures of the server and the client
    struct hostent *servent;    // network host entry required by gethostbyname()
    char buffer[1024];
    const char *addr = args.netflow_collector;
    const char *port = args.port;
    memset(&server,0,sizeof(server)); // erase the server structure
    server.sin_family = AF_INET;

    //prepares structures for export
    prepare_export(&flow, &header);

    //copy the header and flow structure to the buffer
    memcpy(buffer, &header, sizeof(header));
    memcpy(buffer + sizeof(header), &flow, sizeof(flow));

    // make DNS resolution of the first parameter using gethostbyname()
    // check the first parameter
    if ((servent = gethostbyname(addr)) == nullptr){
        errx(1,"gethostbyname() failed\n");
    }

    // copy the first parameter to the server.sin_addr structure
    memcpy(&server.sin_addr,servent->h_addr,servent->h_length);

    char *endptr;
    // server port (network byte order)
    server.sin_port = htons(strtol(port, &endptr, 10));

    //create a client socket
    if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1){
        err(1,"socket() failed\n");
    }

    //printf("* Server socket created\n");

    msg_size = sizeof(header) + sizeof(flow);

    //printf("* Creating a connected UDP socket using connect()\n");
    // create a connected UDP socket
    if (connect(sock, (struct sockaddr *)&server, sizeof(server))  == -1){
        err(1, "connect() failed");
    }

    //send data to the server
    i = send(sock,buffer,msg_size,0);
    // check if data was sent correctly
    if (i == -1){
        err(1,"send() failed");
    }
    else if (i != msg_size){
        err(1,"send(): buffer written partially");
    }

    close(sock);
    //printf("* Closing the client socket ...\n");
}
