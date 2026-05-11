all: pcap_ex

pcap_ex: pcap_ex.c
	gcc -Wall -o pcap_ex pcap_ex.c -lpcap
	
clean:
	rm -f *.o pcap_ex
