// Functions
#ifndef TRACE_H_ // include guard
#define TRACE_H_

// Structs to hold data for each header
struct pcap_pkthdr_ethernet;
struct pcap_pkthdr_arp;
struct pcap_pkthdr_ip;
struct pcap_pkthdr_icmp;
struct pcap_pkthdr_tcp;
struct pcap_pkthdr_udp;

// Parsing Header Functions
void ethernet_parse(const struct pcap_pkthdr_ethernet *ethernet, struct pcap_pkthdr *header);
void arp_parse(const struct pcap_pkthdr_arp *arp, struct pcap_pkthdr *header);
void ip_parse(const struct pcap_pkthdr_ip *ip, struct pcap_pkthdr *header);
void arp_opcode(uint16_t opcode);
void icmp_parse(const struct pcap_pkthdr_icmp *icmp);
void tcp_parse(const struct pcap_pkthdr_tcp *tcp, uint16_t tcp_segment_len, uint8_t *ip_sender_bufferp, uint8_t *ip_dest_buffer, uint8_t ip_protocol, uint8_t ihl);
void udp_parse(const struct pcap_pkthdr_udp *udp);

// Functions to print 
void ethernet_type(uint16_t e_type);
void ip_protocol(uint8_t protocol);
void icmp_type(uint8_t type);
void tcp_source_port(uint16_t port);
void tcp_dest_port(uint16_t port);
void tcp_flag(const struct pcap_pkthdr_tcp *tcp);
void ip_protocol_parse(const struct pcap_pkthdr_ip *ip, uint8_t ihl, uint8_t *ip_sender_buffer, uint8_t *ip_dest_buffer);
void pseudo_header_function(uint16_t tcp_segment_len, uint8_t *ip_sender_buffer, uint8_t *ip_dest_buffer, uint8_t ip_protocol, uint8_t ihl);
#endif // TRACE_H_
