#include <iostream>
#include <pcap.h>
using namespace std;

int main(int argc, char* argv[]) {
	
	pcap_t *capture;
	char errorBuffer[PCAP_ERRBUF_SIZE];
	int linkType;
	
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

	//Read packets from the file using function pcap_loop().
    
	pcap_close(capture);
	return 0;
}
