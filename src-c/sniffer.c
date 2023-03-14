#include "sniffer.h"
#include <signal.h>

int display_all_device_to_sniff(){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
	int res=pcap_findalldevs(&alldevs, errbuf);
	if (res==-1) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return -1;
	}
	for (pcap_if_t * d = alldevs; d != NULL; d = d->next){
	    printf("Device: %s\n", d->name);
	}
	pcap_freealldevs(alldevs);
	return 0;
}
pcap_t * open_device(char device [], int read_time_out_milliseconds, int promisc_mode){
    char errbuf[PCAP_ERRBUF_SIZE];
    //BUFSIZ is the maximum number of samples a sniffer will
    pcap_t * sniffer_handler= pcap_open_live(device, BUFSIZ, promisc_mode, read_time_out_milliseconds, errbuf);
    return sniffer_handler;

}
int check_data_link_layer_header(pcap_t *  sniffer_handler, int header, char dev []){
     if (pcap_datalink(sniffer_handler) != DLT_EN10MB) {
    	    fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
            return -1;
        }
     return 0;
}
int extract_mac_ip_info(u_char *args, const struct pcap_pkthdr *packet_header,const u_char *packet_body,  char * mac_src, char * mac_dst, char * ip_src, char * ip_dst, char * timestamp )
{

     struct  ether_header * eptr = (struct ether_header *) packet_body;
     //-----get timestamp in proper format
     time_t now= packet_header->ts.tv_sec;
     struct tm *lt = localtime(&now);
     sprintf(timestamp, "%s", asctime(lt));
     timestamp[strlen(timestamp)-1]='\0'; // remove end line that ascitime adds
     //------------ get mac src -- 6 bytes ----------
     sprintf(mac_src,"%02x:%02x:%02x:%02x:%02x:%02x", eptr->ether_shost[0], eptr->ether_shost[1], eptr->ether_shost[2], eptr->ether_shost[3],
     eptr->ether_shost[4], eptr->ether_shost[5]);

     //------------ get mac des -- 6 bytes --------------
     sprintf(mac_dst,"%02x:%02x:%02x:%02x:%02x:%02x", eptr->ether_dhost[0], eptr->ether_dhost[1], eptr->ether_dhost[2], eptr->ether_dhost[3],
     eptr->ether_dhost[4], eptr->ether_dhost[5]);

     if (ntohs(eptr->ether_type) != ETHERTYPE_IP) {
            printf("Skipping...\n\n");
            return -1;
     }

    // --------- getting the ip addresses -------------------------
    // ---------- let me  decapsulate the ethernet packet ---------
    const u_char *ip_header= packet_body + 6+6+2; // 6 for src 6 des 2 for length
    //---------- i will ignore the first 12 bytes as they have other information -----------
    //---------- get ip source address ---------------------------------------
    const u_char * ip_source_address = ip_header + 12;
    sprintf(ip_src,"%d.%d.%d.%d", ip_source_address[0], ip_source_address[1], ip_source_address[2], ip_source_address[3]);

    // -------------- get ip destination address ----------------------
    const u_char * ip_dst_address = ip_source_address + 4;
    sprintf(ip_dst,"%d.%d.%d.%d", ip_dst_address[0], ip_dst_address[1], ip_dst_address[2], ip_dst_address[3]);

   return 0;
}

int apply_filter(char * filter_expression,  pcap_t * sniffer_handler)
{
    struct bpf_program compiled_filter;
    int optimize_expression =0;
    bpf_u_int32 net;
    if (pcap_compile(sniffer_handler, &compiled_filter, filter_expression, optimize_expression, net) == -1) {
    	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_expression, pcap_geterr(sniffer_handler));
    	return -1;
    }
    if (pcap_setfilter(sniffer_handler, &compiled_filter) == -1) {
    	printf("Couldn't install filter %s: %s\n", filter_expression, pcap_geterr(sniffer_handler));
    	return -1;
    }
    return 0;
}
