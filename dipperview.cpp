#include <iostream>
#include <map>
#include <set>
#include <string>
#include <cstring>
#include <pcap.h>
#include <sys/time.h>
#include <net/ethernet.h>
using namespace std;

#define HADDR_BUFLEN 18

void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
bool timeval_isZero(struct timeval tv);
int timeval_subtract(struct timeval *result, struct timeval tv1, struct timeval tv0);
void getHAddr(char hAddr[HADDR_BUFLEN], u_int8_t bytes[ETH_ALEN]);
void printMap(map<string, int> &toPrint);
void printMap(map<string, string> &toPrint);
void mapIncrement(map<string, int> &toUpdate, const string &key);

//statistics
struct timeval g_startTime;
struct timeval g_endTime;
map<string, int> g_etherSenderPacketCounts;
map<string, int> g_etherRecipientPacketCounts;
map<string, int> g_IPSenderPacketCounts;
map<string, int> g_IPRecipientPacketCounts;
map<string, string> g_ARPParticipants;
set<int> g_UDPSourcePorts;
set<int> g_UDPDestPorts;
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
	
    //Create a list of machines participating in ARP, including their associated MAC addresses and, where possible, the associated IP addresses.
    //For UDP, create two lists for the unique ports seen: one for the source ports and one for the destination ports.
    //Report the average, minimum, and maximum packet sizes. The packet size refers to everything beyond the tcpdump header.
	cout<<"Min packet size: "<<g_minPacketSize<<" Bytes"<<endl
		<<"Max packet size: "<<g_maxPacketSize<<" Bytes"<<endl
		<<"Avg packet size: "<<(double)g_totalPacketSize/(double)g_numPackets<<" Bytes"<<endl;
		
	
    //Create two lists, one for unique senders and one for unique recipients, along with the total number of packets associated with each. This should be done at two layers: Ethernet and IP. For Ethernet, represent the addresses in hex-colon notation. For IP addresses, use the standard dotted decimal notation.
	cout<<"Ethernet Senders:"<<endl;
	printMap(g_etherSenderPacketCounts);
	cout<<"Ethernet Recipients:"<<endl;
	printMap(g_etherRecipientPacketCounts);	
	
	return 0;
}

void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
	char hAddr[18] = "";
	cout << "Yay packet" << endl;
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
	
	
}

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

void getHAddr(char hAddr[HADDR_BUFLEN], u_int8_t bytes[ETH_ALEN]) {
	sprintf(hAddr, "%02x:%02x:%02x:%02x:%02x:%02x", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
	return;
}

void printMap(map<string, int> &toPrint) {
	map<string, int>::iterator mapIt;
	for(mapIt = toPrint.begin(); mapIt != toPrint.end(); mapIt++) {
		cout<<mapIt->first<<" "<<mapIt->second<<endl;
	}
	return;
}

void printMap(map<string, string> &toPrint) {
	map<string, string>::iterator mapIt;
	for(mapIt = toPrint.begin(); mapIt != toPrint.end(); mapIt++) {
		cout<<mapIt->first<<" "<<mapIt->second<<endl;
	}
	return;
}

void mapIncrement(map<string, int> &toUpdate, const string &key) {
	if(toUpdate.find(key) == toUpdate.end()) {
		toUpdate[key] = 1;
	}
	else {
		toUpdate[key]++;
	}
	return;
}