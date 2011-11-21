#include <iostream>
#include <map>
#include <set>
#include <string>
#include <cstring>
#include <pcap.h>
#include <sys/time.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
using namespace std;

#define HADDR_BUFLEN 18
#define IPADDR_BUFLEN 16

void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
bool timeval_isZero(struct timeval tv);
int timeval_subtract(struct timeval *result, struct timeval tv1, struct timeval tv0);
void getHAddr(char hAddr[HADDR_BUFLEN], u_int8_t bytes[ETH_ALEN]);
void getIPAddr(char ipAddr[IPADDR_BUFLEN], u_int32_t naddr);
void printMap(map<string, int> &toPrint);
void printArpMap(multimap<string, string> &toPrint);
void printSet(set<u_int16_t> &toPrint);
void mapIncrement(map<string, int> &toUpdate, const string &key);
void arpMapUpdate(multimap<string, string> &toUpdate, u_int8_t ha[ETH_ALEN], u_int8_t pa[4]);

//statistics
struct timeval g_startTime;
struct timeval g_endTime;
map<string, int> g_etherSenderPacketCounts;
map<string, int> g_etherRecipientPacketCounts;
map<string, int> g_IPSenderPacketCounts;
map<string, int> g_IPRecipientPacketCounts;
multimap<string, string> g_ARPParticipants;
set<u_int16_t> g_UDPSourcePorts;
set<u_int16_t> g_UDPDestPorts;
bpf_u_int32 g_minPacketSize = 0xFFFFFFFF;
bpf_u_int32 g_maxPacketSize;
bpf_u_int32 g_totalPacketSize;
bpf_u_int32 g_numPackets;


int main(int argc, char* argv[]) {
	
	pcap_t *capture;
	char errorBuffer[PCAP_ERRBUF_SIZE];
	int linkType;
	int looprv = 0;
	struct tm *ptm = NULL;
	char timeStamp[32] = "";
	struct timeval elapsedTime;
	map<string, int>::iterator countIterator;
	map<string, string>::iterator participantIterator;
	
	g_startTime.tv_sec = 0;
	g_startTime.tv_usec = 0;
	g_endTime.tv_sec = 0;
	g_endTime.tv_usec = 0;
	
	if(argc != 2) {
		cerr << "Must provide one argument:  the filename of a tcpdump file" << endl;
		return -1;
	}
	//open input file
	capture = pcap_open_offline(argv[1], errorBuffer);
	if(capture == NULL) {
		cerr << "pcap_open_offline error: " << errorBuffer << endl;
		return -1;
	}
	
	//check data has been captured from Ethernet
	linkType = pcap_datalink(capture);
	if(linkType != DLT_EN10MB) {
		cerr << "Error: packet does not have Ethernet headers" << endl;
		return -1;
	}

	//-1 count means "read packets until exhausted"
	looprv = pcap_loop(capture, -1, callback, NULL);
	if(looprv == 0) {
		cout << "Packet reading complete" << endl;
	}
	else if(looprv == -2) {
		cerr << "pcap_breakloop was called during pcap_loop" << endl;
		return -1;
	}
	else {
		cerr << "Error during pcap_loop: " << pcap_geterr(capture) << endl;
		return -1;
	}
    
	pcap_close(capture);
	
	//Print the start date and time of the packet capture.
	ptm = gmtime((time_t*)&g_startTime.tv_sec);
	strftime(timeStamp, sizeof(timeStamp), "%Y-%m-%d %H:%M:%S", ptm);
	cout<<"Start time: "<<timeStamp<<" UTC"<<endl;
	
    //Print the duration of the packet capture in seconds with microsecond resolution.
	timeval_subtract(&elapsedTime, g_endTime, g_startTime);
	printf("Packet Capture Duration: %ld.%06ld\n", elapsedTime.tv_sec, elapsedTime.tv_usec);
	
    //Print the total number of packets.
	cout<<"Total number of packets: "<<g_numPackets<<endl;
    //Report the average, minimum, and maximum packet sizes.
	cout<<"Min packet size: "<<g_minPacketSize<<" Bytes"<<endl
		<<"Max packet size: "<<g_maxPacketSize<<" Bytes"<<endl
		<<"Avg packet size: "<<(double)g_totalPacketSize/(double)g_numPackets<<" Bytes"<<endl;
		
	
    //Print unique senders and recipients of Ethernet frames and IP packets
	cout<<endl;
	cout<<"+--------------------+-------+"<<endl
		<<"| Ethernet Senders   | Count |"<<endl;
	printMap(g_etherSenderPacketCounts);
	
	cout<<endl;
	cout<<"+--------------------+-------+"<<endl
		<<"| Ethernet Recipients| Count |"<<endl;
	printMap(g_etherRecipientPacketCounts);	
	
	cout<<endl;
	cout<<"+--------------------+-------+"<<endl
		<<"|     IP Senders     | Count |"<<endl;
	printMap(g_IPSenderPacketCounts);
	
	cout<<endl;
	cout<<"+--------------------+-------+"<<endl
		<<"|    IP Recipients   | Count |"<<endl;
	printMap(g_IPRecipientPacketCounts);
	
    //Print list of ARP Participants (machines make or respond to ARP requests)
	cout<<endl;
	cout<<"+-----------------------------------------+"<<endl
		<<"|             ARP Participants            |"<<endl
		<<"+--------------------+--------------------+"<<endl
		<<"|  Hardware Address  |     IP Address     |"<<endl;
	printArpMap(g_ARPParticipants);
	
    //Print lists of unique UDP source ports and UDP destination ports
	cout<<endl;
	cout<<"+-----------------------+"<<endl
		<<"|   UDP Source Ports    |"<<endl;
	printSet(g_UDPSourcePorts);
	
	cout<<endl;
	cout<<"+-----------------------+"<<endl
		<<"| UDP Destination Ports |"<<endl;
	printSet(g_UDPDestPorts);
	
	
	return 0;
}

//Function to handle a packet
void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
	char hAddr[HADDR_BUFLEN] = "";
	char ipAddr[IPADDR_BUFLEN] = "";
	u_int16_t ether_type;
	//
	// Pcap header
	//
	//time
	if(timeval_isZero(g_startTime) || timeval_subtract(NULL, h->ts, g_startTime) == -1) {
		memcpy(&g_startTime, &(h->ts), sizeof(struct timeval));
	}
	if(timeval_isZero(g_endTime) || timeval_subtract(NULL, h->ts, g_endTime) == 1) {
		memcpy(&g_endTime, &(h->ts), sizeof(struct timeval));
	}
	//packet count
	g_numPackets++;
	//min, max, total
	if(g_minPacketSize > h->len) {
		g_minPacketSize = h->len;
	}
	if(g_maxPacketSize < h->len) {
		g_maxPacketSize = h->len;
	}
	//use portion size to prevent double-counting packets
	g_totalPacketSize += h->caplen;
	
	//
	// Ethernet Header
	//
	struct ether_header *eth = (ether_header *)bytes;
	//sending host
	getHAddr(hAddr, eth->ether_shost);
	mapIncrement(g_etherSenderPacketCounts, hAddr);
	
	//destination host
	getHAddr(hAddr, eth->ether_dhost);
	mapIncrement(g_etherRecipientPacketCounts, hAddr);
	
	ether_type = ntohs(eth->ether_type);
	//Ethernet protocol
	if(ether_type == ETHERTYPE_IP) {
		//
		// IP Header
		//
		struct iphdr *iph = (iphdr *)(bytes+ETH_HLEN);
		//source address
		getIPAddr(ipAddr, iph->saddr);
		mapIncrement(g_IPSenderPacketCounts, ipAddr);
		//destination address
		getIPAddr(ipAddr, iph->daddr);
		mapIncrement(g_IPRecipientPacketCounts, ipAddr);
		
		//check for UDP
		if(iph->protocol == IPPROTO_UDP) {
			//
			// UDP Header
			//
			struct udphdr *udph = (udphdr *)(bytes+ETH_HLEN+(iph->ihl)*4);
			g_UDPSourcePorts.insert(ntohs(udph->source));
			g_UDPDestPorts.insert(ntohs(udph->dest));
		}
	}
	else if(ether_type == ETHERTYPE_ARP) {
		struct ether_arp *arph = (ether_arp *)(bytes+ETH_HLEN);
		arpMapUpdate(g_ARPParticipants, arph->arp_sha, arph->arp_spa);
	}
}

//Determines if a timeval struct is 0.
bool timeval_isZero(struct timeval tv) {
	return tv.tv_sec == 0 && tv.tv_usec == 0;
}

//subtract tv0 from tv1, store result in result (if not null)
//if tv1 > tv0, return 1
//if tv1 < tv0, return -1
//if tv1 = tv0, return 0
int timeval_subtract(struct timeval *result, struct timeval tv1, struct timeval tv0) {
	long int diffSeconds = (tv1.tv_sec - tv0.tv_sec);
	long int diffMicroSeconds = (tv1.tv_usec - tv0.tv_usec);
	if(diffMicroSeconds < 0) {
		diffSeconds--;
		diffMicroSeconds += 1000000;
	}
	if(result != NULL) {
		result->tv_sec = diffSeconds;
		result->tv_usec = diffMicroSeconds;
	}
	if(diffSeconds > 0) {
		return 1;
	}
	else if(diffSeconds < 0) {
		return -1;
	}
	else if(diffMicroSeconds > 0) {
		return 1;
	}
	else if(diffMicroSeconds < 0) {
		return -1;
	}
	else {
		return 0;
	}
}

//Get hardware (MAC) address string from the bytes representing the address in the Ethernet header
void getHAddr(char hAddr[HADDR_BUFLEN], u_int8_t bytes[ETH_ALEN]) {
	sprintf(hAddr, "%02x:%02x:%02x:%02x:%02x:%02x", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
	return;
}

//Get an IP address string from a 32-bit integer from the IP header (assume network byte order)
void getIPAddr(char ipAddr[IPADDR_BUFLEN], u_int32_t naddr) {
	u_int32_t haddr;
	haddr = ntohl(naddr);
	sprintf(ipAddr, "%d.%d.%d.%d", (haddr&0xFF000000)>>24, (haddr&0xFF0000)>>16, (haddr&0xFF00)>>8, haddr&0xFF);
	return;
}

void printMap(map<string, int> &toPrint) {
	map<string, int>::iterator mapIt;
	printf("+--------------------+-------+\n");
	for(mapIt = toPrint.begin(); mapIt != toPrint.end(); mapIt++) {
		printf("| %-18s | %5d |\n", mapIt->first.c_str(), mapIt->second);
	}
	printf("+--------------------+-------+\n");
	return;
}

void printArpMap(multimap<string, string> &toPrint) {
	map<string, string>::iterator mapIt;
	printf("+--------------------+--------------------+\n");
	for(mapIt = toPrint.begin(); mapIt != toPrint.end(); mapIt++) {
		printf("| %-18s | %-18s |\n", mapIt->first.c_str(), mapIt->second.c_str());
	}
	printf("+--------------------+--------------------+\n");
	return;
}

void printSet(set<u_int16_t> &toPrint) {
	set<u_int16_t>::iterator setIt;
	printf("+-----------------------+\n");
	for(setIt = toPrint.begin(); setIt != toPrint.end(); setIt++) {
		printf("|         %5hu         |\n", *setIt);
	}
	printf("+-----------------------+\n");
}

//Given a map and a key, increment the value at the key, or set the value to 1 if it doesn't already exist.
void mapIncrement(map<string, int> &toUpdate, const string &key) {
	if(toUpdate.find(key) == toUpdate.end()) {
		toUpdate[key] = 1;
	}
	else {
		toUpdate[key]++;
	}
	return;
}

//Update the ARP map given a hardware address from the ARP packet and an IP address from the ARP packet
void arpMapUpdate(multimap<string, string> &toUpdate, u_int8_t ha[ETH_ALEN], u_int8_t pa[4]) {
	char hAddr[HADDR_BUFLEN];
	char ipAddr[IPADDR_BUFLEN];
	multimap<string, string>::iterator mapIt;
	getHAddr(hAddr, ha);
	sprintf(ipAddr, "%d.%d.%d.%d", pa[0], pa[1], pa[2], pa[3]);
	if(toUpdate.count(hAddr) != 0) {
		for(mapIt = toUpdate.equal_range(hAddr).first; mapIt != toUpdate.equal_range(hAddr).second; mapIt++) {
			if(mapIt->second == ipAddr) {
				return;
			}
		}
	}
	toUpdate.insert(pair<string, string>(hAddr, ipAddr));
	
	return;
}
