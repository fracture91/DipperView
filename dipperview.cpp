#include <iostream>
#include <pcap.h>
using namespace std;

int main(int argc, char* argv[]) {
	
	pcap_t *capture;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	if(argc != 2) {
		cerr << "Must provide one argument:  the filename of a tcpdump file" << endl;
		return -1;
	}

	capture = pcap_open_offline(argv[1], errbuf);
	if(capture == NULL) {
		cerr << "pcap_open_offline error: " << errbuf << endl;
		return -1;
	}

	//Check that the data you are provided has been captured from Ethernet using function pcap_datalink().

	//Read packets from the file using function pcap_loop().
    
	pcap_close(capture);
	return 0;
}
