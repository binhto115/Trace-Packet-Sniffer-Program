# CPE-464-Introduction-to-Computer-Networks

trace is a packet sniffer program written in C/C++ that analyzes network packets from a capture file and outputs protocol header information for various network layers.
Instead of capturing live network traffic, this program reads pre-captured packet trace files (in .pcap format) using the pcap library — the same library used by tools like Wireshark and tcpdump.

Usage: ./trace <pcap_file>
