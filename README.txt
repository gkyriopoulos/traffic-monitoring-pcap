gcc (Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0

This is my packet sniffing tool
It filters:
1)All non TCP/UDP packets
2)All trafic to a specific port(eg "port 8080")

When live capture is on it will save all captured packets that 
sucessfully passed through the filters in the file 
captured_packets.pcap

Also a log.txt file will be generated with all the information
that the excresise asked for.

I also added some extra information at the total stats. 

The extra functionalities and information where added so 
I could confirm that the program was indeed functioning as intended.

I tried to confirm the results that I was getting with Wireshark.

In order to run the program follow these steps:
1)make
2a)For live capture use:
sudo ./pcap_ex -i "interface" (e.g interface = eth0)
2b)For capturing from a file use:
sudo ./pcap_ex -r "file" (e.g fie = test_pcap_5mins.pcap)
3)Filter expressions can be used both with live and with file capture
An example could be:
sudo ./pcap_ex -i "interface" -f “port_expression” (e.g interface = eth0 , port_expression = "port 8080")

Note:
As I was doing the assigment I tried to confrim the results I was getting 
using Wireshark. The filter expressions and the TCP/UDP packet filter
I believe are working fine and as intended. 
On the other hand the count_retransmission function() I made, I believe that 
it is wrong. It gives a way to big amount of retransmissions. Even though
I believe that I used the same algorirthm that Wireshark uses as described 
here on the "TCP Retransmission" section:

https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html

This is the only issue I encountered with this assigment.
