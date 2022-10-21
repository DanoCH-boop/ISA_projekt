// nazov: isa_netgen.cpp
// popis: Generování NetFlow dat ze zachycené síťové komunikace
// autor: Daniel Chudý, xchudy06, VUT FIT Brno
// 20.10.2022

#include <pcap.h>
#include <cstdio>
#include <string>
#include <cstring>
#include <ctime>
#include <sys/types.h>
#include <sys/socket.h>
#include <getopt.h>

#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if_arp.h>
#include <arpa/inet.h>

//https://cfengine.com/blog/2021/optional-arguments-with-getopt-long/, Lars E.
#define OPTIONAL_ARGUMENT_IS_PRESENT \
    ((optarg == NULL && optind < argc && argv[optind][0] != '-') \
     ? (bool) (optarg = argv[optind++]) \
     : (optarg != NULL))
#define LINE_LEN_MAX 16
#define SIZE_ETHERNET 14
#define SIZE_IPV6 40
#define TO_MS 1000
#define PROMISC 1
#define IPV4_T 2048
#define IPV6_T 34525
#define ARP_T 2054

char errbuff[PCAP_ERRBUF_SIZE];	// Error string 

using namespace std;

/**
 * @brief print the timestamp in RFC3339
 * 
 * @param ts Structure cotaining sec and usec in unixtime
 * @note https://stackoverflow.com/a/48772690, chux - Reinstata Monica
 * @return void
*/
void print_ts(timeval ts) {
    auto ms = to_string(ts.tv_usec/1000);
    string timestamp;
    struct tm *p = localtime(&ts.tv_sec);
    char buf[100];
    strftime(buf, sizeof buf - 1, "%FT%T%z", p);
    string ts_no_ms = string(buf);
    string tz = ts_no_ms.substr(ts_no_ms.size()-5);
    ts_no_ms.erase(ts_no_ms.size()-5);
    ts_no_ms.append(".");
    ts_no_ms.append(ms);
    tz.insert(3,":");
    ts_no_ms.append(tz);
    timestamp = ts_no_ms;

    printf("%s\n", timestamp.c_str());
}

/**
 * @brief prints the data of a packet in hexadecimal format
 *
 * @param payload data to be printed
 * @param len length of a line
 * @param offset marks the start of a line
 * @note Taken and slightly modified from: https://www.tcpdump.org/other/sniffex.c Cartens T.
 * @return void
*/
void print_hex_ascii_line(const u_char *payload, unsigned len, unsigned int offset)
{

    unsigned int i;
    unsigned int gap;
    const u_char *ch;

    // offset
    printf("0x");
    printf("%04d: ", offset);

    // hex
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        // print extra space after 8th byte for visual aid
        if (i == 7)
            printf(" ");
    }
    // print space to handle line less than 8 bytes
    if (len < 8)
        printf(" ");

    // fill hex gap with spaces if not full line
    if (len < LINE_LEN_MAX) {
        gap = LINE_LEN_MAX - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf(" ");

    // ascii, if not printable, print "."
    ch = payload;
    for(i = 0; i < len; i++) {
        if (!isprint(*ch))
            printf(".");
        else
            printf("%c", *ch);
        ch++;
    }

    printf("\n");
}

/**
 * @brief helper function for printing packet data
 *
 * @param payload data to be printed
 * @param len len of data
 * @note Taken and slightly modified from: https://www.tcpdump.org/other/sniffex.c Cartens T.
 * @return void
*/
void print_data(const u_char *payload, unsigned int len) {
    unsigned int line_len;
    unsigned int offset = 0;
    const u_char *ch = payload;

	printf("\n");

    // no data present
    if (len <= 0)
        return;

    // data fits on one line
    if (len <= LINE_LEN_MAX) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    // data spans multiple lines
    while(true) {
        // compute current line length
        line_len = LINE_LEN_MAX % len;
        // print line
        print_hex_ascii_line(ch, line_len, offset);
        // compute total remaining
        len = len - line_len;
        // shift pointer to remaining bytes to print
        ch = ch + line_len;
        // add offset
        offset = offset + 10;
        // check if we have line width chars or less
        if (len <= LINE_LEN_MAX) {
            // print last line and get out
            print_hex_ascii_line(ch, len, offset);
            break;
        }
    }

}

/**
 * @brief prints ports of a tcp packet
 *
 * @param packet pointer to the packet data
 * @param ip_hl length of the IP header
 * @param tot_len total length of the frame without ethernet header
 * @return void
*/
void tpc_fun(const u_char *packet, unsigned int ip_hl, unsigned int tot_len) {
    auto _tcp = (tcphdr*)(packet + SIZE_ETHERNET + ip_hl);

    printf("src port: %d\n", ntohs(_tcp->th_sport));
    printf("dst port: %d\n", ntohs(_tcp->th_dport));

    auto data = (u_char *)(packet);

    print_data(data, tot_len + SIZE_ETHERNET);
}

/**
 * @brief prints ports of a udp packet
 *
 * @param packet pointer to the packet data
 * @param ip_hl length of the IP header
 * @param tot_len total length of the frame without ethernet header
 * @return void
*/
void udp_fun(const u_char *packet, unsigned int ip_hl, unsigned int tot_len) {
    auto _udp = (udphdr*)(packet + SIZE_ETHERNET + ip_hl);

    printf("src port: %d\n", ntohs(_udp->uh_sport));
    printf("dst port: %d\n", ntohs(_udp->uh_dport));

    auto data = (u_char *)(packet);

    print_data(data, tot_len + SIZE_ETHERNET);
}

/**
 * @brief helper function for printing icmp packet data
 *
 * @param packet pointer to the packet data
 * @param ip_hl length of the IP header
 * @param tot_len total length of the frame without ethernet header
 * @return void
*/
void icmp_fun(const u_char *packet, unsigned int ip_hl, unsigned int tot_len) {
    auto data = (u_char *)(packet);

    print_data(data, tot_len + SIZE_ETHERNET);
}

/**
 * @brief prints ipv4 adresses, determines the transport layer protocol
 *
 * @param packet pointer to the packet data
 * @note https://stackoverflow.com/a/5328184, Milan
 * @return void
*/
void ipv4_fun(const u_char *packet) {
    auto ipv4 = (iphdr *)(packet + SIZE_ETHERNET);
    auto ipv4_hl = ipv4->ihl * (unsigned)4;

    auto tot_len = ntohs(ipv4->tot_len);

    char saddr[INET_ADDRSTRLEN];
    char daddr[INET_ADDRSTRLEN];

    inet_ntop(AF_INET,&(ipv4->saddr),saddr,INET_ADDRSTRLEN);
    inet_ntop(AF_INET,&(ipv4->daddr),daddr,INET_ADDRSTRLEN);

    // print source and destination IP addresses
    printf("src IP: %s\n", saddr);
    printf("dst IP: %s\n", daddr);

    // determine protocol
    //printf("%u", ipv4->protocol);
    switch (ipv4->protocol) {
        case IPPROTO_TCP:
            printf("Protocol: TCP\n");
            tpc_fun(packet, ipv4_hl, tot_len);
            break;
        case IPPROTO_UDP:
            printf("Protocol: UDP\n");
            udp_fun(packet, ipv4_hl, tot_len);
            break;
        case IPPROTO_ICMP:
            printf("Protocol: ICMP\n");
            icmp_fun(packet, ipv4_hl, tot_len);
            break;
        default:
            fprintf(stderr,"Unrecognized protocol\n");
            exit(1);
    }
}

/**
 * @brief prints ipv6 adresses, determines the transport layer protocol
 *
 * @param packet pointer to the packet data
 * @param header_len length of the whole frame
 * @note https://stackoverflow.com/a/5328184, Milan
 * @return void
*/
void ipv6_fun(const u_char *packet, unsigned int header_len) {
    auto ipv6 = (ip6_hdr *)(packet + SIZE_ETHERNET);

    char saddr[INET_ADDRSTRLEN];
    char daddr[INET_ADDRSTRLEN];

    inet_ntop(AF_INET6,&(ipv6->ip6_src),saddr,INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6,&(ipv6->ip6_dst),daddr,INET6_ADDRSTRLEN);

    // print source and destination IP addresses
    printf("src IP: %s\n", saddr);
    printf("dst IP: %s\n", daddr);

    // determine protocol
    switch (ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
        case IPPROTO_TCP:
            printf("Protocol: TCP\n");
            tpc_fun(packet,SIZE_IPV6, header_len - SIZE_ETHERNET);
            break;
        case IPPROTO_UDP:
            printf("Protocol: UDP\n");
            udp_fun(packet, SIZE_IPV6, header_len - SIZE_ETHERNET);
            break;
        case IPPROTO_ICMPV6:
            printf("Protocol: ICMP\n");
            icmp_fun(packet, SIZE_IPV6, header_len - SIZE_ETHERNET);
            break;
        default:
            fprintf(stderr,"Unrecognized protocol\n");
            exit(1);
    }
}

/**
 * @brief callback function, prints MAC adresses, determines the network layer protocol
 * 
 * @param packet pointer to the packet data
 * @param header_len length of the whole frame
 * @note https://stackoverflow.com/a/6063122, Cedric J.
 * @return void
*/
void returned_packet(u_char *fargs, const struct pcap_pkthdr *header, const u_char *packet)
{
    //print timtestamp in RFC3339
    print_ts(header->ts);
    
    // define ethernet header
    auto ethernet = (ether_header*)(packet);

    printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ethernet->ether_shost[0],ethernet->ether_shost[1],
           ethernet->ether_shost[2],ethernet->ether_shost[3],
           ethernet->ether_shost[4],ethernet->ether_shost[5]);
    printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ethernet->ether_dhost[0],ethernet->ether_dhost[1],
           ethernet->ether_dhost[2],ethernet->ether_dhost[3],
           ethernet->ether_dhost[4],ethernet->ether_dhost[5]);

    printf("frame length: %d", header->len);
    printf(" bytes\n");

    switch (ntohs(ethernet->ether_type)) {
        case IPV4_T :
            ipv4_fun(packet);
            break;
        case IPV6_T :
            ipv6_fun(packet, header->len);
            break;
        default:
            fprintf(stderr,"Unrecognized ether type\n");
            exit(1);
    }

}

//https://cfengine.com/blog/2021/optional-arguments-with-getopt-long/
int main(int argc, char **argv)
{        
    string interfaces = "all";
    const struct option long_options[] = {
        {"interface", optional_argument, nullptr, 'i'},
        {"tcp", no_argument, nullptr, 't'},
        {"udp", no_argument, nullptr, 'u'},
        {"arp", no_argument, nullptr, 'a'},
        {"icmp", no_argument, nullptr, 'c'},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, no_argument, nullptr, 0}};
    int opt;

    opt = getopt(argc, argv, "i::p:tun:") != -1;
    while (opt)
    {
        switch (opt){

            case 'i' :
                if(OPTIONAL_ARGUMENT_IS_PRESENT){
                    interfaces = optarg;
                }
                break;     
            case 't' :
                tcp = true;
                break;
            case 'u' :
                udp = true;
                break;

            case 'a' :
                arp = true;
                break;

            case 'c' :
                icmp = true;
                break;

            case 'p' :
                port = stoi(optarg);
                if(port < 0){
                    fprintf(stderr,"port num cannot be negative\n");
                }            
                break;

            case 'n' :
                n = stoi(optarg);
                if(n < 1){
                    fprintf(stderr,"count of frames cannot be negative\n");
                }                   
                break;

            case '?' :
            case ':' :
            case 'h' :
            	printf("napoveda:\n");
                printf("./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n");
                printf("\t-i -- interface eth0 - právě jedno rozhraní, na kterém se bude poslouchat\n"
                       "\t-p port - filtrování paketů podle portu; nebude-li tento parametr uveden, uvažují se všechny porty\n"
                       "\t-t --tcp (bude zobrazovat pouze TCP pakety)\n"
                       "\t-u --udp (bude zobrazovat pouze UDP pakety)\n"
                       "\t--icmp (bude zobrazovat pouze ICMPv4 a ICMPv6 pakety)\n"
                       "\t--arp (bude zobrazovat pouze ARP rámce)\n"
                       "\t-n num - určuje počet paketů\n"
                       "\t-h --help - vypisanie tejto napovedy\n");
                exit(1);
            default:
                fprintf(stderr,"Invalid argument");
                break;
        
        }
        opt = getopt(argc, argv, "i::p:tun:", nullptr) != -1;
    }

    const char* fl_exp;
    fl_exp = "tcp or udp or icmp";

    pcap_t *handle;			        // Session handle
	struct bpf_program fp{};		// The compiled filter
	bpf_u_int32 mask;		        // Our netmask
	bpf_u_int32 net;		        // Our IP

	// Define the device
	const char *interface = interfaces.c_str();
	// Find the properties for the device
	if (pcap_lookupnet(interface, &net, &mask, errbuff) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", interface, errbuff);
		net = 0;
		mask = 0;
	}
	// Open the session in promiscuous mode
	handle = pcap_open_offline(interface, BUFSIZ, PROMISC, TO_MS, errbuff);
	if (!handle) {
		fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuff);
		exit(1);
	}

    if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", interface);
		exit(1);
	}

	// Compile and apply the filter
	if (pcap_compile(handle, &fp, fl_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", fl_exp, pcap_geterr(handle));
		exit(1);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", fl_exp, pcap_geterr(handle));
		exit(1);
	}
	// get packets
    pcap_loop(handle, 10, returned_packet, nullptr);
	// clean and close
    pcap_freecode(&fp);
	pcap_close(handle);
	return 0;
}
