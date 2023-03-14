#include "sniffer.h"
#include "kafka_producer.h"
#include "configuration_reader.h"
#include <librdkafka/rdkafka.h>
#include<signal.h>

//callback function will be called by pcap
void handle_incomming_packet(u_char *args, const struct pcap_pkthdr *packet_header,const u_char *packet_body);

//global variables
static rd_kafka_conf_t * producer_conf;
static rd_kafka_t * producer;
static user_config conf;
static int message_key =0;

// to make sure to clean resource before closing
static void handle_close_sig(int sig)
{
        if(producer!=NULL)
        {
            destroy_producer(producer);
        }
        destroy_user_config(&conf);
        printf("No more sniffing all resources have been released!\n");
        exit(0);
}


int main(int argc, char *argv[])
{

     if (signal(SIGINT, handle_close_sig) == SIG_ERR)
           printf("I will terminate");
    //------------------ make sure of correct number of arguments ------------------
    if(argc!=2)
    {
        printf("Usage: sudo myChatter.exe <path to configuration file>\n");
        return 0;
    }
    conf.json_format= "{\"timestamp\":\"%s\",\"mac_src\":\"%s\", \"ip_src\":\"%s\", \"mac_dst\":\"%s\", \"ip_dst\":\"%s\" }";
    // ------------------ parsing configuration file ------------------
    int res = read_configuration_file(argv[1], &conf);
    if(res==-1)
    {
        fprintf(stderr,"failed to read configuration file\n");
        return 0;
    }

    // ------------------ Echo the configuration ------------------------
    printf("Kafka broker: %s\n",conf.broker );
    printf("Kafka topic:  %s\n",conf.topic );
    printf("Network device:  %s\n",conf.device );
    printf("Filter:  %s\n",conf.filter_expression );


    // --------------- initialize the producer
    initialize_producer(conf.broker, conf.topic, &producer, &producer_conf);


    //------------------ display all connected interfaces (devices) ------------
    res=display_all_device_to_sniff();
    if (res==-1)
        return res;

    // ---------------- Open "get a handler" to the specific device -------------
    int read_time_out_milliseconds = 1;
    int promisc_mode=1;
    pcap_t * sniffer_handler = open_device(conf.device, read_time_out_milliseconds, promisc_mode);

    //----------- check the data layer "header" so the pcap understand format of the coming packets ----
    // different headers are here https://www.tcpdump.org/linktypes.html
    res = check_data_link_layer_header(sniffer_handler, DLT_EN10MB, conf.device);
    if(res==-1)
        return 0;

    // ---------- to get the ip address and subnet mask -------------------------
    /*char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 ip; //P address as integer
    bpf_u_int32 subnet_mask; // Subnet mask as integer
    pcap_lookupnet(conf.device, &ip, &subnet_mask,errbuf);

    // ------------- readable format ---------------------------------------------
    struct in_addr address;
    char ip_printable[15];
    char subnet_mask_printable[15];
    address.s_addr = ip;
    strcpy(ip_printable, inet_ntoa(address));
    printf("device %s has IP : %s", conf.device, ip_printable );
    address.s_addr = subnet_mask;
    strcpy(subnet_mask_printable, inet_ntoa(address));
    printf(" Subnet mask %s\n", subnet_mask_printable );*/

#ifdef FILTER
    // if the user wants to filer out message for port 22 or ICMP for ping
    apply_filter(conf.filter_expression, sniffer_handler);
#endif

    // --------------- actual sniffing --------------------------------------------------------------
    const u_char *packet;
    struct pcap_pkthdr packet_header;

    // ----------- capture one by one
    //packet = pcap_next(sniffer_handler, &packet_header); // can be in a busy wait is not efficient

    //------ register handler to capture incoming packets ---------------
    int number_of_packets_to_be_captured=0; // basically endless capture
    printf("Actively sniffing ...........\n");
    pcap_loop(sniffer_handler, number_of_packets_to_be_captured, handle_incomming_packet, NULL);

    printf("done\n");
    pcap_close(sniffer_handler);
	return 0;
}

void handle_incomming_packet(u_char *args, const struct pcap_pkthdr *packet_header,const u_char *packet_body){
     char json_message [1000];
     char mac_src [20];
     char mac_dst [20];
     char ip_dst [20];
     char ip_src [20];
     char timestamp [30];
     int res = extract_mac_ip_info(args,packet_header,packet_body, mac_src, mac_dst, ip_src,ip_dst, timestamp); // handled in sniffer.c and get info in printable format -- I had a bug here last time ip_dst and ip_src were flipped together
     if(res!=0)
        return;

     // ------------display TimeStamp/ MAC and IP addresses -------------------
     printf("at %s SRC MAC address is %s -> DST MAC address is %s ||||| SRC IP address is %s -> DST IP address is %s\n",timestamp, mac_src, mac_dst, ip_src, ip_dst);
     //-------- Adding information in a json formate -----------------
     sprintf(json_message, conf.json_format,timestamp,  mac_src ,ip_src, mac_dst, ip_dst);
     forward_message(message_key, json_message, producer, conf.topic); // handled in kafka_producer.c
     message_key++;
}
