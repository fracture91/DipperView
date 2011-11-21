Author: Eric Finn and Andrew Hurle
Date: 2011-11-21
Project: 2
CS Class: CS 3516
Language: C++

Build: make

Usage: dipperview <filename>
Takes a pcap file and collects various statistics on it:
	o Start date and time of packet capture (UTC)
	o Duration of packet capture
	o Total number of packets captured
	o Min, max, and average packet sizes
	o Ethernet addresses of senders and number of packets sent by each host
	o Ethernet addresses of recipients and number of packets sent to each host
	o IP addresses of senders and number of packets sent by each host
	o IP addresses of recipients and number of packets sent to each host
	o Ethernet and IP addresses of ARP participants
	o A list of all UDP source ports used
	o A list of all UDP destination ports used

Results:
> ./dipperview project2-http.pcap
Packet reading complete
Start time: 2004-05-13 10:17:07 UTC
Packet Capture Duration: 30.393704
Total number of packets: 43
Min packet size: 54 Bytes
Max packet size: 1484 Bytes
Avg packet size: 583.512 Bytes

+--------------------+-------+
| Ethernet Senders   | Count |
+--------------------+-------+
| 00:00:01:00:00:00  |    20 |
| fe:ff:20:00:01:00  |    23 |
+--------------------+-------+

+--------------------+-------+
| Ethernet Recipients| Count |
+--------------------+-------+
| 00:00:01:00:00:00  |    23 |
| fe:ff:20:00:01:00  |    20 |
+--------------------+-------+

+--------------------+-------+
|     IP Senders     | Count |
+--------------------+-------+
| 145.253.2.203      |     1 |
| 145.254.160.237    |    20 |
| 216.239.59.99      |     4 |
| 65.208.228.223     |    18 |
+--------------------+-------+

+--------------------+-------+
|    IP Recipients   | Count |
+--------------------+-------+
| 145.253.2.203      |     1 |
| 145.254.160.237    |    23 |
| 216.239.59.99      |     3 |
| 65.208.228.223     |    16 |
+--------------------+-------+

+-----------------------------------------+
|             ARP Participants            |
+--------------------+--------------------+
|  Hardware Address  |     IP Address     |
+--------------------+--------------------+
+--------------------+--------------------+

+-----------------------+
|   UDP Source Ports    |
+-----------------------+
|            53         |
|          3009         |
+-----------------------+

+-----------------------+
| UDP Destination Ports |
+-----------------------+
|            53         |
|          3009         |
+-----------------------+


> ./dipperview project2-arp-storm.pcap 
Packet reading complete
Start time: 2004-10-05 14:01:05 UTC
Packet Capture Duration: 28.969106
Total number of packets: 622
Min packet size: 60 Bytes
Max packet size: 60 Bytes
Avg packet size: 60 Bytes

+--------------------+-------+
| Ethernet Senders   | Count |
+--------------------+-------+
| 00:07:0d:af:f4:54  |   622 |
+--------------------+-------+

+--------------------+-------+
| Ethernet Recipients| Count |
+--------------------+-------+
| ff:ff:ff:ff:ff:ff  |   622 |
+--------------------+-------+

+--------------------+-------+
|     IP Senders     | Count |
+--------------------+-------+
+--------------------+-------+

+--------------------+-------+
|    IP Recipients   | Count |
+--------------------+-------+
+--------------------+-------+

+-----------------------------------------+
|             ARP Participants            |
+--------------------+--------------------+
|  Hardware Address  |     IP Address     |
+--------------------+--------------------+
| 00:07:0d:af:f4:54  | 24.166.172.1       |
| 00:07:0d:af:f4:54  | 65.28.78.1         |
| 00:07:0d:af:f4:54  | 69.76.216.1        |
| 00:07:0d:af:f4:54  | 65.26.92.1         |
| 00:07:0d:af:f4:54  | 24.145.164.129     |
| 00:07:0d:af:f4:54  | 67.52.222.1        |
| 00:07:0d:af:f4:54  | 69.81.17.1         |
| 00:07:0d:af:f4:54  | 65.26.71.1         |
| 00:07:0d:af:f4:54  | 69.23.182.1        |
+--------------------+--------------------+

+-----------------------+
|   UDP Source Ports    |
+-----------------------+
+-----------------------+

+-----------------------+
| UDP Destination Ports |
+-----------------------+
+-----------------------+


References:
cplusplus.com - C/C++ library functions and classes
linux.die.net - man pages for pcap library
http://en.wikipedia.org/wiki/IPv4#Header - Used as reference on format of the Internet Header Length field of the IP header