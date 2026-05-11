#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
/*These header files contain the necessary structures 
for the ethernet,tcp,upd and ip headers. */
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>

#define SNAPLEN 2048
#define PROMISC 0
#define MAX_MS 1000
#define MAX_PACKETS	0

struct sockaddr_in src,dest;
struct packet* packet_list = NULL;
struct network_flow* network_flow_list = NULL;

int total_network_flows = 0;
int total_udp_network_flows = 0;
int total_tcp_network_flows = 0;
int total_udp_packets = 0;
int total_tcp_packets = 0;
int total_packets = 0; 
int total_bytes_tcp_packets = 0;
int total_bytes_udp_packets = 0;
int total_retransmited = 0;

int total_other_packets = 0;
int total_port_filtered_packets = 0;

int liveCaptureFlag = 0;
int offlineCaptureFlag = 0;
int portFlag = 0;

int port = 0;

struct packet {
	char* source_ip;
	char* dest_ip;
	int source_port;
	int dest_port;
	int ethernet_size;
	int ip_size;
	int protocol_size;
	int payload_size;
	int sequence_number;
	int next_expected_sequence_number;
	int keep_alive;
	int retransmission;

	int th_fin;
	int th_syn;
	int th_rst;

	u_int8_t protocol;

	struct packet* next;
};

struct network_flow {
	char* source_ip;
	char* dest_ip;
	int source_port;
	int dest_port;
	int protocol;

	struct network_flow* next;
};

void interupt_handler();

void packet_handler(u_char *args, const struct pcap_pkthdr *header,const u_char *packet);

void packet_handler_without_write(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body);

struct network_flow* create_network_flow(struct packet* packet);

struct packet* create_tcp_packet(const u_char *packet_body, int packet_size);

struct packet* create_udp_packet(const u_char *packet_body, int packet_size);

struct packet* add_packet(struct packet* packet_list, struct packet* packet, int packet_size);

struct network_flow* add_unique_network_flow(struct network_flow* network_flow_list, struct network_flow* network_flow);

int increase_packet_counters(struct packet* packet, int packet_size);

int increase_network_flow_counters(struct network_flow* network_flow);

int print_packet_info(struct packet* packet, int pack_num, FILE* stream);

int print_total_stats(FILE* stream);

int free_packet_list(struct packet* packet_list);

int free_network_flow_list(struct network_flow* network_flow_list);

int find_retransmittions(struct packet* packet_list);

int main(int argc, char **argv){

	int opt;

	char* interface;
	char* filePath;
	char* filter;
	
	char* port_string;

	/*If an interupt signal occurs call the interupt_handler.*/
	signal(SIGINT, interupt_handler);

	/*Getting the arguements from the command line.*/
	while( (opt = getopt(argc, argv, "i:r:f:h")) != -1 ){
   		switch(opt){
   			case 'i':
   				interface = optarg;
   				printf("%s\n", interface);
   				liveCaptureFlag = 1;
   				break;
   			case 'r':
   				filePath = optarg;
   				printf("%s\n", filePath);
   				offlineCaptureFlag = 1;
   				break;
   			case 'f':
   				filter = optarg;
   				printf("Filter: %s\n", filter);
   				port_string = strtok(filter, " ");
   				if(strcmp(port_string, "port") == 0){
   					port_string = strtok(NULL, " ");
					port = atoi(port_string);
					portFlag = 1;
   				}else{
   					printf("Invalid port expression\n");
   					return -1;
   				}
   				break;
   			case 'h':
   				printf("Options:\n");
   				printf("-i	path	Network interface name(e.g., etho0)\n");
   				printf("-r	path	Packet capture file name(e.g., test.pcap)\n");
   				printf("-f	path	Filter expression(e.g., port 8080)\n");
   				printf("-h	help	This help message\n");
   				return 0;
   			case '?':
   				fprintf(stderr, "Unknown option use -h for help.\n");
   				return -1;
		}	
	}
	
	/*Some varriables required for the pcap library*/
	pcap_t* handle;
	pcap_dumper_t * dumper;

	/*The error buffer.*/
	char errbuf[PCAP_ERRBUF_SIZE];

	printf("Starting the packet sniffing process >:D\n");
	printf("You can send a SIGINT signal in order to stop the capturing\n");
	printf("The packets captured will be saved on captured_packets.pcap\n");
	printf("...\n");
	if(liveCaptureFlag){
		
		/*Removing the log.txt if it already exists.*/
		remove("log.txt");

		/*Create a pcap_t handle*/
		handle = pcap_open_live(interface, SNAPLEN, PROMISC, MAX_MS, errbuf);

		/*If an error exists stop.*/
		if (handle == NULL) {
			fprintf(stderr,"%s\n", errbuf);
			return -1;
		}

		/*Create a dumper to output the captured packets.*/
		dumper = pcap_dump_open(handle, "captured_packets.pcap");

		/*If an error exists stop.*/
		if (dumper == NULL) {
			fprintf(stderr,"%s\n", errbuf);
			return -1;
		}

		/*Looping through each packet and calling the packet handler_function.
		I am also passing the dumper as arguement.*/
		pcap_loop(handle,MAX_PACKETS,packet_handler,(u_char*) dumper);

		/*Closing stuff.*/
		pcap_close(handle);
		pcap_dump_close(dumper);

	}

	if(offlineCaptureFlag){
		
		/*Create a pcap_t handle*/
		handle  = pcap_open_offline(filePath,errbuf);

		/*If an error exists stop.*/
		if (handle == NULL) {
			fprintf(stderr,"%s\n", errbuf);
		return -1;
		}

		/*Looping through each packet and calling the packet handler_function_without_write function.*/
		pcap_loop(handle,MAX_PACKETS,packet_handler_without_write,NULL);
		pcap_close(handle);

		/*Finding the retransmissions.*/
		find_retransmittions(packet_list);

		/*Printing the total stats to the terminal.*/
		print_total_stats(stdout);
	}


	printf("The packet sniffing process is over *cheers*!\n");

	/*Freeing up used memory for the lists.*/
	free_packet_list(packet_list);
	free_network_flow_list(network_flow_list);
}

void interupt_handler(){
	/*The interput handler, if an interrupt signal occurs find the retransmissions up until this point and 
	print the total stats the appropriate stream.*/
	printf("\nThe process was interupted, the total statistics until now will be displayed inside log.txt if live capture was on.\n");
	if(liveCaptureFlag){
		find_retransmittions(packet_list);
		FILE* fp;
		fp = fopen("log.txt","a+");
		print_total_stats(fp);
		print_total_stats(stdout);
		fclose(fp);
		exit(0);
	}else if(offlineCaptureFlag){
		find_retransmittions(packet_list);
		print_total_stats(stdout);
		exit(0);
	}
}

void packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body){

	/*Opening the log.txt file to append info.*/
	FILE* fp;
	fp = fopen("log.txt","a+");

	/*Necessary structs.*/
	const struct iphdr* ip_header;
	const struct tcphdr* tcp_header;
	const struct udphdr* udp_header; 

	/*Pointers to packets and network flows
	the memory required is allocated at a later stage.*/
	struct network_flow* network_flow;
	struct packet* packet;               

	/*Total packet size.*/
	int packet_size = packet_header->len;
	/*IP header size.*/
	int ip_size;

	/*A varriable used for the transfer protocol.*/
	u_int8_t transfer_protocol;

	static int pack_num = 1;

	/*Getting the IP header of the packet.*/
	ip_header = (struct iphdr*)(packet_body + sizeof(struct ethhdr));
	ip_size = ip_header->ihl*4;

	transfer_protocol = ip_header->protocol;
	switch(transfer_protocol){
		case IPPROTO_TCP:
			/*Getting the TCP header of the packet.*/
			tcp_header=(struct tcphdr*)(packet_body + ip_size + sizeof(struct ethhdr));
			/*If the packet's port is equal to the port specified from the user filter it.*/
			if( (portFlag = 1) && ( ntohs(tcp_header->th_sport) == port || ntohs(tcp_header->th_dport) == port) ){
				/*Increasing the total count of filtered ports.*/
				total_port_filtered_packets++;
				return;
			}
			/*If the code reached this point it means that the caught packet is a 
			TCP packet with port numbers different than the filter.
			*/
			/*Create the TCP packet. This is the stage where the required memory is allocated.*/
			packet = create_tcp_packet(packet_body, packet_size);
			/*Add it to the list of valid packets.*/
			packet_list = add_packet(packet_list, packet, packet_size);
			/*Create the packt's network flow. This is the stage where the required memory is allocated.*/
			network_flow = create_network_flow(packet);
			/*If the flow is unique it will be added to the list.*/
			network_flow_list = add_unique_network_flow(network_flow_list, network_flow);
			/*Printing the packet info the to appropriate stream.*/
			print_packet_info(packet, pack_num, fp);
			/*Increasing the pack_num by 1 since this is a valid packet.*/
			pack_num++;
			break;
		case IPPROTO_UDP:
			/*Getting the UDP header of the packet.*/
			udp_header=(struct udphdr*)(packet_body + ip_size + sizeof(struct ethhdr));
			/*If the packet's port is equal to the port specified from the user filter it.*/
			if( (portFlag = 1) && ( ntohs(udp_header->uh_sport) == port || ntohs(udp_header->uh_dport) == port) ){
				/*Increasing the total count of filtered ports.*/
				total_port_filtered_packets++;
				return;
			}
			/*If the code reached this point it means that the caught packet is a 
			UDP packet with port numbers different than the filter.
			*/
			/*Create the UDP packet. This is the stage where the required memory is allocated.*/
			packet = create_udp_packet(packet_body, packet_size);
			/*Add it to the list of valid packets.*/
			packet_list = add_packet(packet_list, packet, packet_size);
			/*Create the packt's network flow. This is the stage where the required memory is allocated.*/
			network_flow = create_network_flow(packet);
			/*If the flow is unique it will be added to the list.*/
			network_flow_list = add_unique_network_flow(network_flow_list, network_flow);
			/*Printing the packet info the to appropriate stream.*/
			print_packet_info(packet, pack_num, fp);
			/*Increasing the pack_num by 1 since this is a valid packet.*/
			pack_num++;
			break;
		default:
			/*If the packet is neither TCP or UDP it's filtered out.*/
			total_other_packets++;
			return ;
	}

	/*Dumping the caught packet to the file.*/
	pcap_dump(args, packet_header, packet_body);

	/*Closing the file stream.*/
	fclose(fp);

    return;
}

void packet_handler_without_write(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body){

	/*Necessary structs.*/
	const struct iphdr* ip_header;
	const struct tcphdr* tcp_header;
	const struct udphdr* udp_header;             	

	/*Pointers to packets and network flows
	the memory required is allocated at a later stage.*/
	struct network_flow* network_flow;
	struct packet* packet;               

	/*Total packet size.*/
	int packet_size = packet_header->len;
	/*IP header size.*/
	int ip_size;

	/*A varriable used for the transfer protocol.*/
	u_int8_t transfer_protocol;

	static int pack_num = 1;

	/*Getting the IP header of the packet.*/
	ip_header = (struct iphdr*)(packet_body + sizeof(struct ethhdr));
	ip_size = ip_header->ihl*4;

	transfer_protocol = ip_header->protocol;
	switch(transfer_protocol){
		case IPPROTO_TCP:
			/*Getting the TCP header of the packet.*/
			tcp_header=(struct tcphdr*)(packet_body + ip_size + sizeof(struct ethhdr));
			/*If the packet's port is equal to the port specified from the user filter it.*/
			if( (portFlag = 1) && ( ntohs(tcp_header->th_sport) == port || ntohs(tcp_header->th_dport) == port) ){
				/*Increasing the total count of filtered ports.*/
				total_port_filtered_packets++;
				return;
			}
			/*If the code reached this point it means that the caught packet is a 
			TCP packet with port numbers different than the filter.
			*/
			/*Create the TCP packet. This is the stage where the required memory is allocated.*/
			packet = create_tcp_packet(packet_body, packet_size);
			/*Add it to the list of valid packets.*/
			packet_list = add_packet(packet_list, packet, packet_size);
			/*Create the packt's network flow. This is the stage where the required memory is allocated.*/
			network_flow = create_network_flow(packet);
			/*If the flow is unique it will be added to the list.*/
			network_flow_list = add_unique_network_flow(network_flow_list, network_flow);
			/*Printing the packet info the to appropriate stream.*/
			print_packet_info(packet, pack_num, stdout);
			/*Increasing the pack_num by 1 since this is a valid packet.*/
			pack_num++;
			break;
		case IPPROTO_UDP:
			/*Getting the UDP header of the packet.*/
			udp_header=(struct udphdr*)(packet_body + ip_size + sizeof(struct ethhdr));
			/*If the packet's port is equal to the port specified from the user filter it.*/
			if( (portFlag = 1) && ( ntohs(udp_header->uh_sport) == port || ntohs(udp_header->uh_dport) == port) ){
				total_port_filtered_packets++;
				return;
			}
			/*If the code reached this point it means that the caught packet is a 
			UDP packet with port numbers different than the filter.
			*/
			/*Create the UDP packet. This is the stage where the required memory is allocated.*/
			packet = create_udp_packet(packet_body, packet_size);
			/*Add it to the list of valid packets.*/
			packet_list = add_packet(packet_list, packet, packet_size);
			/*Create the packt's network flow. This is the stage where the required memory is allocated.*/
			network_flow = create_network_flow(packet);
			/*If the flow is unique it will be added to the list.*/
			network_flow_list = add_unique_network_flow(network_flow_list, network_flow);
			/*Printing the packet info the to appropriate stream.*/
			print_packet_info(packet, pack_num, stdout);
			/*Increasing the pack_num by 1 since this is a valid packet.*/
			pack_num++;
			break;
		default:
			/*If the packet is neither TCP or UDP it's filtered out.*/
			total_other_packets++;
			return ;
	}

    return;
}

int print_total_stats(FILE* stream){
	fprintf(stream,"------------------------Total stats----------------------\n");
	fprintf(stream,"|	*Network flows			:	%d\n", total_network_flows);
	fprintf(stream,"|	*TCP network flows		:	%d\n", total_tcp_network_flows);
	fprintf(stream,"|	*UDP network flows		:	%d\n", total_udp_network_flows);
	fprintf(stream,"|	*TCP packets			:	%d\n", total_tcp_packets);
	fprintf(stream,"|	*UDP packets			:	%d\n", total_udp_packets);
	fprintf(stream,"|	*Other packets			:	%d\n", total_other_packets);
	fprintf(stream,"|	*Packets transmitted		:	%d\n", total_packets + total_other_packets + total_port_filtered_packets);
	fprintf(stream,"|	*Port filtered packets		:	%d\n", total_port_filtered_packets);
	fprintf(stream,"|	*Total filtered packets		:	%d\n", total_other_packets + total_port_filtered_packets);
	fprintf(stream,"|	*Packets received		:	%d\n", total_packets);
	fprintf(stream,"|	*TCP packets bytes received	:	%d\n", total_bytes_tcp_packets);
	fprintf(stream,"|	*UDP packets bytes received	:	%d\n", total_bytes_udp_packets);
	fprintf(stream,"|	*Rentransmitted received	:	%d\n", total_retransmited);
	fprintf(stream,"|---------------------------------------------------------\n");

	return 1;
}

int print_packet_info(struct packet* packet, int pack_num, FILE* stream){

	fprintf(stream,"---------------------------------------------------------\n");
	fprintf(stream,"|	Packet num: %d\n", pack_num);
	fprintf(stream,"---------------------------------------------------------\n");

	if(packet->protocol == IPPROTO_TCP){
		fprintf(stream,"|	*Protocol type		:	TCP\n");
		fprintf(stream,"|	*Source IP		:	%s\n" , packet->source_ip);
		fprintf(stream,"|	*Destination IP		:	%s\n" , packet->dest_ip);
		fprintf(stream,"|	*Source Port		:	%d\n" , packet->source_port);
		fprintf(stream,"|	*Destination Port	:	%d\n" , packet->dest_port);
		fprintf(stream,"|	*TCP Header Length	:	%d  bytes\n" , packet->protocol_size);
		fprintf(stream,"|	*Payload Lenth		:	%d  bytes\n" , packet->payload_size);
		fprintf(stream,"|	*Payload Address	:	%p\n", packet + (packet->ethernet_size + packet->ip_size + packet->protocol_size));
		fprintf(stream,"|	*Retransmitted		:	%d\n", packet->retransmission);
	}else if(packet->protocol == IPPROTO_UDP){
		fprintf(stream,"|	*Protocol type		:	UDP\n");
		fprintf(stream,"|	*Source IP		:	%s\n" , packet->source_ip);
		fprintf(stream,"|	*Destination IP		:	%s\n" , packet->dest_ip);
		fprintf(stream,"|	*Source Port		:	%d\n" , packet->source_port);
		fprintf(stream,"|	*Destination Port	:	%d\n" , packet->dest_port);
		fprintf(stream,"|	*TCP Header Length	:	%d  bytes\n" , packet->protocol_size);
		fprintf(stream,"|	*Payload Lenth		:	%d  bytes\n" , packet->payload_size);
		fprintf(stream,"|	*Payload Address	:	%p\n", packet + (packet->ethernet_size + packet->ip_size + packet->protocol_size));
	}

	return 1;
}

struct packet* create_tcp_packet(const u_char *packet_body, int packet_size){

	struct iphdr* ip_header;            
	struct tcphdr* tcp_header;
	int ip_size;
	int tcp_size;

	/*Allocating space for the struct.*/
	struct packet* packet = (struct packet *)malloc(sizeof(struct packet));
	if(packet == NULL){
		fprintf(stderr,"Error while allocating memory for the TCP packet.");
	}

	/*Getting the packet's IP header.*/
	ip_header = (struct iphdr*)(packet_body + sizeof(struct ethhdr));
	/*Getting the packet's IP size.*/
	ip_size = ip_header->ihl*4;

	/*Allocating memory for the source and destination addresses.*/
	memset(&src, 0, sizeof(src));
	memset(&dest, 0, sizeof(dest));

	src.sin_addr.s_addr = ip_header->saddr;
	dest.sin_addr.s_addr = ip_header->daddr;

	/*Saving the source and destination addresses to the packet struct.*/
	packet->source_ip = strdup(inet_ntoa(src.sin_addr));
	packet->dest_ip = strdup(inet_ntoa(dest.sin_addr));

	/*Saving the packet's protocol.*/
	packet->protocol = ip_header->protocol;

	/*Getting the packet's TCP header.*/
	tcp_header=(struct tcphdr*)(packet_body + ip_size + sizeof(struct ethhdr));
	/*Getting the packet's TCP size.*/
	tcp_size = tcp_header->th_off*4;

	/*Saving the source and destination ports.*/
	packet->source_port = ntohs(tcp_header->source);
	packet->dest_port = ntohs(tcp_header->dest);
	
	/*Getting the ethernet's size (padding including).*/
	packet->ethernet_size = packet_size - ntohs(ip_header->tot_len);
	/*Saving the ip_size*/
	packet->ip_size = ip_size;
	/*Saving the tcp_size.*/
	packet->protocol_size = tcp_size;
	/*Saving the payload size.*/
	packet->payload_size =  ntohs(ip_header->tot_len) - ip_size - tcp_size;
	/*Saving the sequence number.*/
	packet->sequence_number = ntohl(tcp_header->th_seq);
	/*Saving the expected sequence number.*/
	packet->next_expected_sequence_number = ntohl(tcp_header->th_seq) + packet->payload_size;

	/*Saving these flags, they are used at a later stage.*/
	packet->th_fin = tcp_header->th_flags & TH_FIN;
	packet->th_syn = tcp_header->th_flags & TH_SYN;
	packet->th_rst = tcp_header->th_flags & TH_RST;

	/*If the packet it's FIN or SYN it means that 1 shoud be added to the expected sequence number
	according to theory.*/
	if( packet->th_fin || packet->th_syn ){
		packet->next_expected_sequence_number = packet->next_expected_sequence_number + 1;
	}

	/*Checking if the packet is keepalive according to wireshark.*/
	if( (packet->payload_size <= 1) && (packet->sequence_number == packet->next_expected_sequence_number - 1) 
		&& !(packet->th_fin || packet->th_syn || packet->th_rst) ){
		packet->keep_alive = 1;
	}else{
		packet->keep_alive = 0;
	}	

	/*We can't decide about retransmissions yet thus it's left at zero.*/
	packet->retransmission = 0;

	/*The next packet is obviously null since it doesnt exist yet.*/
	packet->next = NULL;

	return packet;
}	


struct packet* create_udp_packet(const u_char *packet_body, int packet_size){

	struct iphdr* ip_header;            
	struct udphdr* udp_header;
	int ip_size;
	int udp_size;

	/*Allocating space for the struct.*/
	struct packet* packet = (struct packet *)malloc(sizeof(struct packet));
	if(packet == NULL){
		fprintf(stderr,"Error while allocating memory for the UDP packet.");
	}
	/*Getting the packet's IP header.*/
	ip_header = (struct iphdr*)(packet_body + sizeof(struct ethhdr));
	/*Getting the packet's IP header size.*/
	ip_size = ip_header->ihl*4;

	/*Allocating memory for the source and destination addresses.*/
	memset(&src, 0, sizeof(src));
	memset(&dest, 0, sizeof(dest));

	src.sin_addr.s_addr = ip_header->saddr;
	dest.sin_addr.s_addr = ip_header->daddr;

	/*Saving the source and destination addresses to the packet struct.*/
	packet->source_ip = strdup(inet_ntoa(src.sin_addr));
	packet->dest_ip = strdup(inet_ntoa(dest.sin_addr));

	/*Saving the packet's protocol.*/
	packet->protocol = ip_header->protocol;

	/*Getting the packet's UDP header.*/
	udp_header=(struct udphdr*)(packet_body + ip_size + sizeof(struct ethhdr));
	/*Getting the packet's UDP size.*/
	udp_size = sizeof(udp_header);

	/*Saving the source and destination ports.*/
	packet->source_port = ntohs(udp_header->source);
	packet->dest_port = ntohs(udp_header->dest);
	
	/*Getting the ethernet's size (padding including).*/
	packet->ethernet_size = packet_size - ntohs(ip_header->tot_len);
	/*Saving the ip_size*/
	packet->ip_size = ip_size;
	/*Saving the tcp size*/
	packet->protocol_size = udp_size;
	/*Saving the payload*/
	packet->payload_size = ntohs(ip_header->tot_len) - ip_size - udp_size;

	/*I dont need these for UDP's since we can't be sure if they are retransmitted or not.*/
	packet->sequence_number = 0;
	packet->next_expected_sequence_number = 0;
	packet->th_fin = 0;
	packet->th_syn = 0;
	packet->th_rst = 0;
	packet->keep_alive = 0;
	packet->retransmission = 0;

	/*The next packet is obviously null since it doesnt exist yet.*/
	packet->next = NULL;

	return packet;
}	

struct network_flow* create_network_flow(struct packet* packet){

	/*Allocating memory for the network flow.*/
	struct network_flow* network_flow = (struct network_flow*)malloc(sizeof(struct network_flow));
	if(network_flow == NULL){
		fprintf(stderr,"Error while allocating memory for the network flow.");
	}
	/*Intializing the struct nothing special.*/
	network_flow->source_ip = strdup(packet->source_ip);;
	network_flow->dest_ip = strdup(packet->dest_ip);
	network_flow->source_port = packet->source_port;
	network_flow->dest_port = packet->dest_port;
	network_flow->protocol = packet->protocol;

	/*The next packet is obviously null since it doesnt exist yet.*/
	network_flow->next = NULL;

	return network_flow;
}

struct packet* add_packet(struct packet* packet_list, struct packet* packet, int packet_size){

	struct packet* current = packet_list;

	/*If the list is empty this is our first packet.*/
	if(current == NULL){
		increase_packet_counters(packet, packet_size);
		return packet;
	}

	/*If not find the last packet.*/
	while(current->next != NULL){
		current = current->next;
	}

	/*Connect the last packet with the given packet.*/
	current->next = packet;

	// printf("Sequence number: %u\n", packet->sequence_number);
	// printf("Next next_expected_sequence_number: %u\n", packet->next_expected_sequence_number);
	// printf("Payload size: %d\n", packet->payload_size);

	/*We added the packet and we need to increase the counters.*/
	increase_packet_counters(packet, packet_size);


	return packet_list;
}

struct network_flow* add_unique_network_flow(struct network_flow* network_flow_list, struct network_flow* network_flow){

	struct network_flow* current = network_flow_list;

	/*If the list is empty this is our first network flow.*/
	if(current == NULL){
		increase_network_flow_counters(network_flow);
		return network_flow;
	}

	/*If not find the last network flow.*/
	while(current->next != NULL){
		/*If the network flow exists don't add it to the list.*/
		if( (strcmp(current->source_ip, network_flow->source_ip) == 0 ) && (strcmp(current->dest_ip, network_flow->dest_ip) == 0 )
		&& (current->source_port == network_flow->source_port) && (current->dest_port == network_flow->dest_port)
		&& (current->protocol == network_flow->protocol) ){
			/*If it already exists free the network_flow and return.*/
			free(network_flow);
			return network_flow_list;
		}
		current = current->next;
	}

	/*Connect the last network flow with the given flow.*/
	current->next = network_flow;
	/*Increasing the network flow counters.*/
	increase_network_flow_counters(network_flow);

	return network_flow_list;
}

int increase_packet_counters(struct packet* packet, int packet_size){

	/*Pretty self-explanatory. Nothing special.*/

	if(packet->protocol == IPPROTO_TCP){
		total_tcp_packets++;
		total_bytes_tcp_packets += packet_size;
	}

	if(packet->protocol == IPPROTO_UDP){
		total_udp_packets++;
		total_bytes_udp_packets += packet_size;
	}

	total_packets++;

	return 1;
}	

int increase_network_flow_counters(struct network_flow* network_flow){

	/*Pretty self-explanatory. Nothing special.*/

	if(network_flow->protocol == IPPROTO_TCP){
		total_tcp_network_flows++;
	}

	if(network_flow->protocol == IPPROTO_UDP){
		total_udp_network_flows++;
	}

	total_network_flows++;

	return 1;
}

int free_packet_list(struct packet* packet_list){

	struct packet* tmp;
	/*Looping throught the list and freeing the memory up.*/
	while(packet_list != NULL){
		tmp = packet_list; 
		packet_list = packet_list->next;
		free(tmp);
	}

	return 1;
}

int free_network_flow_list(struct network_flow* network_flow_list){

	struct network_flow* tmp;
	/*Looping throught the list and freeing the memory up.*/
	while(network_flow_list != NULL){
		tmp = network_flow_list; 
		network_flow_list = network_flow_list->next;
		free(tmp);
	}

	return 1;
}

int find_retransmittions(struct packet* packet_list){

	struct packet* current = packet_list;

	if(current == NULL){
		return 0;
	}

	while(current->next != NULL){

		if( (current->protocol == IPPROTO_TCP) && (current->keep_alive == 0) 
		&& ((current->payload_size > 0) || ((current->th_fin) == 1) || ((current->th_syn) == 1))
		&& (current->next_expected_sequence_number > current->sequence_number) ){
			current->retransmission = 1;
			total_retransmited++;
		}

		current = current->next;
	}

	return 1;
}
