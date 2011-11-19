#include <iostream>
#include <pcap.h>
using namespace std;

void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes); 

int main(int argc, char* argv[]) {
	
	pcap_t *capture;
	char errorBuffer[PCAP_ERRBUF_SIZE];
	int linkType;
	int looprv = 0;
	
	if(argc != 2) {
		cerr << "Must provide one argument:  the filename of a tcpdump file" << endl;
		return -1;
	}

	capture = pcap_open_offline(argv[1], errorBuffer);
	if(capture == NULL) {
		cerr << "pcap_open_offline error: " << errorBuffer << endl;
		return -1;
	}
	
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
	return 0;
}

void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
	cout << "Yay packet" << endl;
}
