// nazov: isa_netgen.cpp
// popis: Generování NetFlow dat ze zachycené síťové komunikace
// autor: Daniel Chudý, xchudy06, VUT FIT Brno
// 20.10.2022
// znovupoužitý kód z projektu ZETA: Packet sniffer z predmetu IPK

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

int n = 1;
int port = -1;
bool tcp = false, udp = false, arp = false, icmp = false;

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
 * @brief callback function, prints MAC adresses, determines the network layer protocol
 * 
 * @param packet pointer to the packet data
 * @param header_len length of the whole frame
 * @note https://stackoverflow.com/a/6063122, Cedric J.
 * @return void
*/
void returned_packet(u_char *fargs, const struct pcap_pkthdr *header, const u_char *packet)
{
	static int i = 1; 
	
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
        case ARP_T :
            arp_fun(packet, header->len);
            break;
        default:
            fprintf(stderr,"Unrecognized ether type\n");
            exit(1);
    }

    if(i != n)
    	printf("\n\n");
    i++;
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
		
    while ((opt = getopt_long(argc, argv, "i::p:tun:", long_options, nullptr)) != -1)
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
    }
	
    // no filter parametres set == all filter parameters set
    if (!udp && !tcp && !icmp && !arp) {
        icmp = true;
        arp = true;
        udp = true;
        tcp = true;
    }

    if(interfaces == "all"){
        print_interfaces();
        return 0;
    }

    string fl_exp;
    fl_exp = make_filter(fl_exp);
    const char *filter_exp = fl_exp.c_str();

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
	handle = pcap_open_live(interface, BUFSIZ, PROMISC, TO_MS, errbuff);
	if (!handle) {
		fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuff);
		exit(1);
	}

    if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", interface);
		exit(1);
	}

	// Compile and apply the filter
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(1);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(1);
	}
	// get packets
    pcap_loop(handle, n, returned_packet, nullptr);
	// clean and close
    pcap_freecode(&fp);
	pcap_close(handle);
	return 0;
}
