#ifndef SRC_SNIFFER
#define SRC_SNIFFER

#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include<netinet/if_ether.h>
#include <sys/time.h>
#include <time.h>

int display_all_device_to_sniff();
pcap_t * open_device(char device [], int read_time_out_milliseconds, int promisc_mode);
int check_data_link_layer_header(pcap_t *  sniffer_handler, int header, char dev []);
int extract_mac_ip_info(u_char *args, const struct pcap_pkthdr *packet_header,const u_char *packet_body, char * mac_src, char * mac_dst, char * ip_src, char * ip_dst, char * timestamp );
int apply_filter(char * filter_expression,  pcap_t * sniffer_handler);
#endif