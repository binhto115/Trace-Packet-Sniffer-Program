#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <sys/types.h>
#include "trace.h"
#include <string.h>
#include "checksum.h"

#define ETHERNET_SIZE 14 // dest MAC (6), source MAC (6), type (2)
#define DEST_MAC_SIZE 6
#define SRC_MAC_SIZE 6
#define ARP_SENDER_MAC_SIZE 6
#define ARP_TARGET_MAC_SIZE 6
#pragma pack(1)

/* 
   Useful Linux cmd 
   Press ESC ->
 	d#d to delete lines and u for undo
	#yy to copy and p for paste
*/

// Ethernet Header
struct pcap_pkthdr_ethernet {
	uint8_t ethernet_dest_addr[DEST_MAC_SIZE]; // (1 byte)
	uint8_t ethernet_src_addr[SRC_MAC_SIZE]; // (1 byte)
	uint16_t ethernet_type; //same as unsigned short (2 tytes)	
};

// ARP Header 
struct pcap_pkthdr_arp {
	uint16_t arp_hardware_type;
	uint16_t arp_protocol_type;
	uint8_t arp_hardware_size;
	uint8_t arp_protocol_size;	
	uint16_t arp_opcode;
	uint8_t arp_sender_mac[ARP_SENDER_MAC_SIZE];
	uint32_t arp_sender_ip;
	uint8_t arp_target_mac[ARP_TARGET_MAC_SIZE];
	uint32_t arp_target_ip; 	
};

//  IP Header
struct pcap_pkthdr_ip {
	uint8_t ip_version;
	uint8_t ip_service;
	uint16_t ip_total_len;
	uint16_t ip_identification;
	uint16_t ip_flag;
	uint8_t ip_ttl;
	uint8_t ip_protocol;
	uint16_t ip_check_sum;
	uint32_t ip_sender;
	uint32_t ip_dest;	
};

// TCP Header
struct pcap_pkthdr_tcp {
	uint16_t tcp_source_port;
	uint16_t tcp_dest_port;
	uint32_t tcp_sequence_num;
	uint32_t tcp_ack;
	uint8_t tcp_data_offset;
	uint8_t tcp_flag;
	uint16_t tcp_window;
	uint16_t tcp_checksum;
	uint16_t tcp_urget_pt;	
};

// UDP Header
struct pcap_pkthdr_udp {
	uint16_t udp_source;
	uint16_t udp_dest;
};

// ICMP Header
struct pcap_pkthdr_icmp {
	uint8_t icmp_type;
};


// Initializing const struct pointer for each header for struct accessibility 
const struct pcap_pkthdr_ethernet *ethernet; // Ethernet header
const struct pcap_pkthdr_arp *arp; // ARP header
const struct pcap_pkthdr_ip *ip; // IP header
const struct pcap_pkthdr_tcp *tcp; // TCP header
const struct pcap_pkthdr_icmp *icmp; // ICMP header
const struct pcap_pkthdr_udp *udp; // UDP header

const uint8_t *packet; // The actual packet buffer 
int counter = 0; // To keep track of packet number 

// Function to parse Ethernet 
void ethernet_parse(const struct pcap_pkthdr_ethernet *ethernet, struct pcap_pkthdr *header) {
	// Reminder: 
	// ethernet = (struct pcap_pkthdr_ethernet *)(packet);
	
	printf("\n");
	printf("Packet number: %d  Packet Len: %d\n", counter, header->len);
	printf("\n");
 	printf("\tEthernet Header\n");
	
	// Print out the Dest MAC
	printf("\t\tDest MAC: %x:%x:%x:%x:%x:%x\n", 
		ethernet->ethernet_dest_addr[0], ethernet->ethernet_dest_addr[1], ethernet->ethernet_dest_addr[2],
		ethernet->ethernet_dest_addr[3], ethernet->ethernet_dest_addr[4], ethernet->ethernet_dest_addr[5]);
        
	// Print out the Source MAC				
	printf("\t\tSource MAC: %x:%x:%x:%x:%x:%x\n",
		ethernet->ethernet_src_addr[0], ethernet->ethernet_src_addr[1], ethernet->ethernet_src_addr[2],	
		ethernet->ethernet_src_addr[3], ethernet->ethernet_src_addr[4], ethernet->ethernet_src_addr[5]);
		
	ethernet_type(ethernet->ethernet_type);	// function to determine EtherType (ARP or IP)
}

// Function to parse ARP
void arp_parse(const struct pcap_pkthdr_arp *arp, struct pcap_pkthdr *header) {
	// Typecast pointer to struct to pointing to unsigned int of 8 bits
	uint8_t *sender_ip_bytes;
	uint8_t *target_ip_bytes;
	sender_ip_bytes = (uint8_t *)(&arp->arp_sender_ip);
        target_ip_bytes = (uint8_t *)(&arp->arp_target_ip);
	
	// Print out the ARP header
	printf("\n");
	printf("\tARP header\n");
	arp_opcode(arp->arp_opcode); // function to determine opcode (0 or 1)
	
	// Print out the Sender MAC
	printf("\t\tSender MAC: %x:%x:%x:%x:%x:%x\n", 
		arp->arp_sender_mac[0], arp->arp_sender_mac[1], arp->arp_sender_mac[2],
		arp->arp_sender_mac[3], arp->arp_sender_mac[4], arp->arp_sender_mac[5]);
	
	// Print out the Sender IP
	printf("\t\tSender IP: %u.%u.%u.%u\n",
		sender_ip_bytes[0], sender_ip_bytes[1], sender_ip_bytes[2], sender_ip_bytes[3]);
	
	// Print out the Target MAC	
	printf("\t\tTarget MAC: %x:%x:%x:%x:%x:%x\n",
		arp->arp_target_mac[0], arp->arp_target_mac[1], arp->arp_target_mac[2],
		arp->arp_target_mac[3], arp->arp_target_mac[4], arp->arp_target_mac[5]);
	
	// Print out the Target IP
	printf("\t\tTarget IP: %u.%u.%u.%u\n",
		target_ip_bytes[0], target_ip_bytes[1], target_ip_bytes[2], target_ip_bytes[3]);
}

// Function to parse IP
void ip_parse(const struct pcap_pkthdr_ip *ip, struct pcap_pkthdr *header) {
	uint8_t ihl = ip->ip_version & 0x0F; // Calculate IHL	
	
	// Print out the IP header
	printf("\n");
	printf("\tIP Header\n");
	printf("\t\tIP PDU Len: %u\n", ntohs(ip->ip_total_len)); // Print out IP total length
	printf("\t\tHeader Len (bytes): %u\n", ihl*4); // Print out IP header length
	printf("\t\tTTL: %u\n", ip->ip_ttl); // Print out Time to Live 
	ip_protocol(ip->ip_protocol); // function to determine IP protocol (TCP, ICMP, or UDP)
		
	// Calculate IP checksum
	if (in_cksum((unsigned short *)(packet + 14), ihl*4) == 0) {	
		printf("\t\tChecksum: Correct (0x%04x)\n", ntohs(ip->ip_check_sum));
	} else {
		printf("\t\tChecksum: Incorrect (0x%04x)\n", ntohs(ip->ip_check_sum));
	}		
	
	// Create buffers to parse IP sender and dest 	
	uint8_t ip_sender_buffer[4];
	uint8_t ip_dest_buffer[4];
	memcpy(ip_sender_buffer, &(ip->ip_sender), 4);
	memcpy(ip_dest_buffer, &(ip->ip_dest), 4);

	// Print out Sender IP
	printf("\t\tSender IP: %u.%u.%u.%u\n", ip_sender_buffer[0], ip_sender_buffer[1], ip_sender_buffer[2],ip_sender_buffer[3]);
	// Print out Dest IP
	printf("\t\tDest IP: %u.%u.%u.%u\n", ip_dest_buffer[0], ip_dest_buffer[1], ip_dest_buffer[2], ip_dest_buffer[3]);

			
	// Parsing Protocols
	// TCP, ICMP, or UDP header starts after IP header length + ethernet header length
	ip_protocol_parse(ip, ihl, ip_sender_buffer, ip_dest_buffer);	
}

// Function to parse TCP
void tcp_parse(const struct pcap_pkthdr_tcp *tcp, uint16_t tcp_segment_len, uint8_t *ip_sender_buffer, uint8_t *ip_dest_buffer, uint8_t ip_protocol, uint8_t ihl) {
	// Print the TCP header 
	printf("\n");
	printf("\tTCP Header\n");
	
	// Print out the TCP segment length
	printf("\t\tSegment Length: %u\n", tcp_segment_len);		

	// function to determine port (HTTP or some rando port)
	tcp_source_port(tcp->tcp_source_port);

	// function to determine port (HTTP or some rando port)
	tcp_dest_port(tcp->tcp_dest_port);

	// Print out seg num
	printf("\t\tSequence Number: %u\n", ntohl(tcp->tcp_sequence_num));
	
	// Print out ACK num
	printf("\t\tACK Number: %u\n", ntohl(tcp->tcp_ack));

	// Print out data offset in bytes
	printf("\t\tData Offset (bytes): %u\n", (tcp->tcp_data_offset >> 4)*4);
	
	// Print out flag bits thru bit manipulation
	tcp_flag(tcp);	
	
	// Print out window size
	uint16_t window;
	memcpy(&window, &(tcp->tcp_window), 2);
	printf("\t\tWindow Size: %u\n", ntohs(window));
	
	// TCP Checksum Pseudo-header
	pseudo_header_function(tcp_segment_len, ip_sender_buffer, ip_dest_buffer, ip_protocol, ihl);
}


// Function to parse ICMP 
void icmp_parse(const struct pcap_pkthdr_icmp *icmp) {
	// Print out the ICMP header
	printf("\n");	
	printf("\tICMP Header\n");
	icmp_type(icmp->icmp_type);
}

// Function to parse UDP
void udp_parse(const struct pcap_pkthdr_udp *udp) {
	// Print out the UDP header
	printf("\n");
	printf("\tUDP Header\n");
	
	// Determine source ports
	if (ntohs(udp->udp_source) == 53) {
		printf("\t\tSource Port:  DNS\n");
	} else {
		printf("\t\tSource Port:  %u\n", ntohs(udp->udp_source));	
	}
	
	// Determine dest ports
	if (ntohs(udp->udp_dest) == 53) { 
		printf("\t\tDest Port:  DNS\n");
	} else {
		printf("\t\tDest Port:  %u\n", ntohs(udp->udp_dest));
	}
}

int main(int argc, char *argv[]) {
	// make sure the cmd run is only two arguments: ./trace and a .pcap file
	if (argc != 2) {
		printf("Incorrect number of arguments\n");
		return 1;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_offline(argv[1], errbuf);

	//  File dne if null
	if (handle == NULL) {
		printf("File does not exist!\n");
		return 1;
	}

	// Read packets of a .pcap file
	struct pcap_pkthdr *header;
	while (pcap_next_ex(handle, &header, &packet) >= 0) {	
		// Typecast ethernet header 
		ethernet = (struct pcap_pkthdr_ethernet *)(packet);
		
		counter++; // Count the packet number
		ethernet_parse(ethernet, header); // call Ethernet parsing function
		
		// Checking to see if it's IP or ARP
		if (ntohs(ethernet->ethernet_type) == 0x0806) { 	
			arp = (struct pcap_pkthdr_arp *)(packet + ETHERNET_SIZE);
			arp_parse(arp, header);	// call ARP parsing function
		} else if (ntohs(ethernet->ethernet_type) == 0x0800) {
			ip = (struct pcap_pkthdr_ip *)(packet + ETHERNET_SIZE);
			ip_parse(ip, header);
		} else {
			break;
		}	
	}
	
	pcap_close(handle);
	return 0;
}

// Ethernet Type Print-out function
void  ethernet_type(uint16_t e_type) {
	switch(ntohs(e_type)) {
		case 0x0806:
               		printf("\t\tType: ARP\n");           
                       	break;
		case 0x0800: 
                        printf("\t\tType: IP\n");
			break;
                default:
			printf("\t\tType: Unknown\n");                                                                                                  
			break; 
	}
}


// ARP Opcode Print-put function
void arp_opcode(uint16_t opcode) {
	switch(ntohs(arp->arp_opcode)) {
		case 1:
			printf("\t\tOpcode: Request\n");
			break;
		case 2:
			printf("\t\tOpcode: Reply\n");
			break;
		default:
			printf("\t\tOpcode: Unknown\n");
			break;				
	}
}

// IP Protocol Print-out function
void ip_protocol(uint8_t protocol) {
	switch(ip->ip_protocol) {
		case 1:
			printf("\t\tProtocol: ICMP\n");
			break;
		case 6:
			printf("\t\tProtocol: TCP\n");
			break;
		case 17:
			printf("\t\tProtocol: UDP\n");
			break;
		default:
			printf("\t\tProtocol: Unknown\n");
			break;
	}
}

// ICMP Type Print-out function
void icmp_type(uint8_t type) {
	switch(icmp->icmp_type) {
		case 0:
			printf("\t\tType: Reply\n");
			break;
		case 8:
			printf("\t\tType: Request\n");
			break;
		case 109:
			printf("\t\tType: 109\n");
			break;
		default:
			printf("\t\tType: Unknown\n");
			break;		
	}
}

// TCP Source Port Print-out function
void tcp_source_port(uint16_t port) {
	switch (ntohs(tcp->tcp_source_port)) {
		case 80:
			printf("\t\tSource Port:  HTTP\n");
			break;
		default: 
			printf("\t\tSource Port:  %u\n", ntohs(tcp->tcp_source_port));
			break;			
	}
}

// TCP Dest Port Print-out function
void tcp_dest_port(uint16_t port) {
	switch (ntohs(tcp->tcp_dest_port)) {
		case 80:
			printf("\t\tDest Port:  HTTP\n");
			break;
		default: 
			printf("\t\tDest Port:  %u\n", ntohs(tcp->tcp_dest_port));
			break;			
	}
}

// TCP flag Print-out function
void tcp_flag(const struct pcap_pkthdr_tcp *tcp) {
	// Flags underneath:
	/* 0000 0000 0000 0000
	 * 0000 0000 0001 0000 = 0x0010 for ACK
	 * 0000 0000 0000 0100 = 0x0004 for RST
	 * 0000 0000 0000 0010 = 0x0002 for SYN
	 * 0000 0000 0000 0001 = 0x0001 for FIN
	*/

	uint16_t flag_buffer; // 12 buts, use 16 bits to hold
	memcpy(&flag_buffer, &(tcp->tcp_flag), sizeof(tcp->tcp_flag));	

	if (flag_buffer & 0x0002) {
		printf("\t\tSYN Flag: Yes\n");
	} else {
		printf("\t\tSYN Flag: No\n");
	}

	if (flag_buffer & 0x0004) {
		printf("\t\tRST Flag: Yes\n");
	} else {
		printf("\t\tRST Flag: No\n");
	}

	if (flag_buffer & 0x0001) {
		printf("\t\tFIN Flag: Yes\n");
	} else {
		printf("\t\tFIN Flag: No\n");
	}

	if (flag_buffer & 0x0010) {
		printf("\t\tACK Flag: Yes\n");
	} else {
		printf("\t\tACK Flag: No\n");
	}
}

// IP Protocol Parsing function
void ip_protocol_parse(const struct pcap_pkthdr_ip *ip, uint8_t ihl, uint8_t *ip_sender_buffer, uint8_t *ip_dest_buffer) {
	// Parsing Protocols
	// TCP, ICMP, or UDP header starts after IP header length + ethernet header length
	if (ip->ip_protocol == 1) {	
		// Parse ICMP header
		icmp = (struct pcap_pkthdr_icmp *)(packet + ETHERNET_SIZE + ihl*4); // Typecasting ptr to icmp stuct
		icmp_parse(icmp);
	} else if (ip->ip_protocol == 6) {
		// Parse TCP header
		tcp = (struct pcap_pkthdr_tcp *)(packet + ETHERNET_SIZE + ihl*4); // Typecasting ptr to tcp truct
		uint16_t tcp_segment_len = ntohs(ip->ip_total_len) - ihl*4; // Calculate TCP segment length
	
		// Function to parse TCP segment 
		tcp_parse(tcp, tcp_segment_len, ip_sender_buffer, ip_dest_buffer, ip->ip_protocol, ihl);
	} else if (ip->ip_protocol == 17) {
		// Parse UDP header
		udp = (struct pcap_pkthdr_udp *)(packet + ETHERNET_SIZE + ihl*4); // Typecasting ptr to udp struct
		udp_parse(udp);
	}
}

// Pseudo-header Parsing function
void pseudo_header_function(uint16_t tcp_segment_len, uint8_t *ip_sender_buffer, uint8_t *ip_dest_buffer, uint8_t ip_protocol, uint8_t ihl) {
	// Initializing variables to contain data
	uint16_t host_tcp_segment_length = tcp_segment_len;
	uint16_t network_tcp_segment_length = htons(host_tcp_segment_length);
	uint8_t pseudo_tcp[12]; // A buffer of size 12 bytes to hold the pseudo header
	size_t offset = 0;

	// Memcpy data in the preudo-header order
	memcpy((pseudo_tcp + offset), (ip_sender_buffer), 4);
	offset += 4; // increment offset 
	memcpy(pseudo_tcp + offset, (ip_dest_buffer), 4);
	offset += 4;

	pseudo_tcp[offset++] = 0x0; // Add reserved after dest
	pseudo_tcp[offset++] = ip_protocol; // Add IP protocol after reserved	
	memcpy((pseudo_tcp + offset), &network_tcp_segment_length, sizeof(network_tcp_segment_length)); // Add TCP segment length in network byte
	
	// Combining the pseudo-header and TCP Segment
	uint8_t tcp_pseudo_tcp_segment[host_tcp_segment_length + 12];
	memcpy(tcp_pseudo_tcp_segment, pseudo_tcp, 12);		
	uint8_t *tcp_segment_start = (uint8_t *)(packet + ETHERNET_SIZE + ihl*4);
	memcpy(tcp_pseudo_tcp_segment + 12, tcp_segment_start, host_tcp_segment_length);	

	// Calculate TCP checksum
	if (in_cksum((unsigned short *)(tcp_pseudo_tcp_segment), host_tcp_segment_length + 12) == 0) {
		printf("\t\tChecksum: Correct (0x%04x)\n", ntohs(tcp->tcp_checksum));
	} else {
		printf("\t\tChecksum: Incorrect (0x%04x)\n", ntohs(tcp->tcp_checksum));
	}
}
