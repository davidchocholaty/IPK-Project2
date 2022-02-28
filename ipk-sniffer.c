/**********************************************************/
/*                                                        */
/* File: ipk-sniffer.c                                    */
/* Created: 2022-02-12                                    */
/* Last change: 2022-02-28                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project 2 for course IPK                      */
/* Description: Packet sniffer                            */
/*                                                        */
/**********************************************************/

#include "ipk-sniffer.h"
#include "packet-print.h"

/* Handle for packet sniffing */
pcap_t *handle;

/*
 * Function for check if interface
 * is validly set
 *
 * Valid combination:
 * opt->interface->interface_set = SET (true)
 * opt->interface->interface_val != ""
 *
 * @param opt User input options
 * return     If interface is validly set true, false otherwise
 */
bool valid_interface (option_t opt)
{       
    bool is_valid = false;
    bool is_set = opt->interface->interface_set;
    char *val = opt->interface->interface_val;

    if (is_set && strcmp(val, "") != 0)
    {
        is_valid = true;
    }

    return is_valid;
}

/*
 * Function for creating filter for packet filtering
 *
 * @param opt    User input options
 * @param filter Buffer for filter string
 */
void create_filter (option_t opt, char *filter)
{
    /*
     * The longest possible version of filter string:
     *
     * tcp port <port> or udp port <port> or icmp port <port> or icmp6 port <port> or arp port <port>
     */
    
    bool port_is_set = opt->port->port_set;
    char port_filter[PORT_FILTER_MAX_LEN];

    strcpy(filter, "");

    /* TCP  */
    if (opt->tcp_set)
    {
        ADD_TCP_FILTER(opt, filter, port_filter, port_is_set);                
    }
    
    /* UDP  */
    if (opt->udp_set)
    {
        ADD_UDP_FILTER(opt, filter, port_filter, port_is_set);
    }

    /* ICMP */
    if (opt->icmp_set)
    {
        ADD_ICMP_FILTER(opt, filter, port_filter, port_is_set);
    }

    /* ARP  */
    if (opt->arp_set)
    {
        ADD_ARP_FILTER(opt, filter, port_filter, port_is_set);
    }
    
    /*
     * If no option tcp, udp, icmp, arp was not set
     *
     * -> sniff every packet
     */
    if (strcmp(filter, "") == 0)
    {
        ADD_TCP_FILTER(opt, filter, port_filter, port_is_set);
        ADD_UDP_FILTER(opt, filter, port_filter, port_is_set);
        ADD_ICMP_FILTER(opt, filter, port_filter, port_is_set);
        ADD_ARP_FILTER(opt, filter, port_filter, port_is_set);
    }
}

/*
 * Function for creating pcap handle for packet sniffing
 *
 * @param device Network device
 * @param filter Filter string
 * @return       Pcap handler
 */
pcap_t *create_pcap_handle (char *device, const char *filter)
{
    char err_buf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    struct bpf_program bpf;
    bpf_u_int32 netmask;
    bpf_u_int32 src_ip;    

    /* Get network device source IP address and netmask */
    if (pcap_lookupnet(device, &src_ip, &netmask, err_buf) == PCAP_ERROR)
    {
		print_error(PCAP_LOOKUPNET_ERR);
        return NULL;
    }

    /* Open the device for live capture in promiscuous mode */
    if ((handle = pcap_open_live(device, BUFSIZ, 1, 1000, err_buf)) == NULL)
    {
		print_error(PCAP_OPEN_LIVE_ERR);
        return NULL;
    }

    /* Convert the packet filter expression into a packet filter binary */
    if (pcap_compile(handle, &bpf, (char *)filter, 0, netmask) == PCAP_ERROR)
    {
    	print_error(PCAP_COMPILE_ERR);
        return NULL;
    }

    /* Bind the packet filter to the libpcap handle */
    if (pcap_setfilter(handle, &bpf) == PCAP_ERROR)
    {
    	print_error(PCAP_SETFILTER_ERR);
        return NULL;
    }

    return handle;    
}

/*
 * Function for handling IPv4 packets
 *
 * @param packet_ptr    Pointer to packet
 * @param packet_header Header of packet
 */
void handle_ipv4_packet (const u_char *packet_ptr, const struct pcap_pkthdr *packet_header)
{
    struct ip *ip_header = (struct ip *)(packet_ptr + sizeof(struct ethhdr));
    int size = packet_header->len;

    /* Parse and display the fields based on the type of hearder: tcp, udp, icmp or arp */
    switch (ip_header->ip_p)
    {
    /* TCP    */
    case IPPROTO_TCP:    
	print_tcp_packet(packet_ptr, size);		
        break;
    
    /* UDP    */
    case IPPROTO_UDP:
	print_udp_packet(packet_ptr, size);
        break;

    /* ICMPv4 */
    case IPPROTO_ICMP:
	print_icmp_packet(packet_ptr, size);
        break;

    /* ARP    */    
    default:
	print_arp_frame(packet_ptr, size);
        break;
    }
}

/*
 * Function for handling IPv6 packets
 *
 * @param packet_ptr    Pointer to packet
 * @param packet_header Header of packet
 */
void handle_ipv6_packet (const u_char *packet_ptr, const struct pcap_pkthdr *packet_header)
{
    struct ip6_hdr *ipv6_header = (struct ip6_hdr *)(packet_ptr + sizeof(struct ethhdr));
    int size = packet_header->len;
    int next_header = ipv6_header->ip6_nxt;

    /* Determining if the packet has an extended header  */
    switch (next_header)
    {
    /* Routing             */
    case IPPROTO_ROUTING:;
        struct ip6_rthdr *header_r = (struct ip6_rthdr*)packet_ptr;
        packet_ptr += sizeof(struct ip6_rthdr);
        next_header = header_r->ip6r_nxt;
        break;
    
    /* Hop by hop          */
    case IPPROTO_HOPOPTS:;
        struct ip6_hbh *header_h = (struct ip6_hbh*)packet_ptr;
        packet_ptr += sizeof(struct ip6_hbh);
        next_header = header_h->ip6h_nxt;
        break;

    /* Fragmentation       */
    case IPPROTO_FRAGMENT:;
        struct ip6_frag *header_f = (struct ip6_frag*)packet_ptr;
        packet_ptr += sizeof(struct ip6_frag);
        next_header = header_f->ip6f_nxt;
        break;

    /* Destination options */
    case IPPROTO_DSTOPTS:;
        struct ip6_dest *header_d = (struct ip6_dest*)packet_ptr;
        packet_ptr += sizeof(struct ip6_dest);
        next_header = header_d->ip6d_nxt;
        break;    

    default:
        break;
    }

    /* Parse and display the fields based on the type of hearder: tcp, udp, icmpv6 */
    switch (next_header)
    {
    /* TCP                 */
    case IPPROTO_TCP:
	print_ipv6_tcp_packet(packet_ptr, size);
        break;

    /* UDP                 */
    case IPPROTO_UDP:
	print_ipv6_udp_packet(packet_ptr, size);
        break;

    /* ICMPv6              */
    case IPPROTO_ICMPV6:
	print_ipv6_icmp_packet(packet_ptr, size);		
        break;
    
    default:
        break;
    }
}

/*
 * Function works as packet handler
 * 
 * This function choose version of packet
 * for following processing (IPv4 or IPv6)
 *
 * @param user          Unused
 * @param packet_header Packet header
 * @param packet_ptr    Pointer to packet
 */
void packet_handler(u_char *user, const struct pcap_pkthdr *packet_header, const u_char *packet_ptr)
{
    /* For compiler to dont show warning about unused variable */
    UNUSED(user);
    
    /* Timestamp */
    if (print_timestamp(&(packet_header->ts)) != EXIT_SUCCESS)
    {
    	print_error(TIME_ERROR);
        exit(EXIT_FAILURE);
    }

    /***************************************************************************/

    /*
     * Next part of code is taken over from following source:
     *
     * https://stackoverflow.com/questions/21222369/getting-ip-address-of-a-packet-in-pcap-file
     * 
     * Author of the answer: user15829861 (https://stackoverflow.com/users/15829861/user15829861)
     */    

    /*
     * For an Ethernet packet, the destination Ethernet
     * address is in bytes 0 through 5, the source Ethernet
     * address is in bytes 6 through 11, and the type/length
     * field is in bytes 12 and 13.
     *
     * It's a big-endian value, so fetch the first byte, at
     * an offset of 12, and put it in the upper 8 bits of
     * the value, and then fetch the second byte, at an offset
     * of 13, and put it in the lower 8 bits of the value.
     */
    int packet_type = ((int)packet_ptr[12] << 8) | (int)packet_ptr[13];

    /***************************************************************************/

    /* IPv6 packet_type */
    if (packet_type == IPv6_PACKET_TYPE)
    {
        handle_ipv6_packet(packet_ptr, packet_header);
    }
    else
    {
        /* IPv4 packet type */
        handle_ipv4_packet(packet_ptr, packet_header);
    }
}

/*
 * Function for stop packet capturing
 */
void stop_capture()
{
    pcap_close(handle);
    exit(EXIT_SUCCESS);
}

/*
 * Main function of packet sniffer
 */
int main (int argc, char *argv[])
{
    option_t opt = NULL;
    char *device = NULL;
    char filter[FILTER_MAX_LEN];
    unsigned long packet_cnt;

    INIT_OPT(opt);

    /* Parse arguments */
    if (parse_args(argc, argv, opt) != EXIT_SUCCESS)
    {
        print_error(OPT_ERROR);
        return EXIT_FAILURE;
    }

    /* Help printing */
    if (opt->help_set == SET)
    {
        print_help(argv[0]);    
    }
    else
    {
    	/* Check if interface is validly set */
        if (!valid_interface(opt))
        {
	       	print_interfaces();
	        return EXIT_FAILURE;
        }

        signal(SIGINT, stop_capture);
        signal(SIGTERM, stop_capture);
        signal(SIGQUIT, stop_capture);
        
        device = opt->interface->interface_val;
        packet_cnt = (opt->num->num_set) ? opt->num->num_val : 1;

        /* Create filter string for packet filtering */
        create_filter(opt, filter);

        /* Create handle */
        handle = create_pcap_handle(device, filter);

        if (handle == NULL)
        {
            return EXIT_FAILURE;
        }

        /* Start the packet capture */
        if (pcap_loop(handle, packet_cnt, packet_handler, (u_char*)NULL) < 0)
        {
			print_error(PCAP_LOOP_ERR);
            return EXIT_FAILURE;
        }
        
        /* Stop the packet capture */
        stop_capture();
    }

    return EXIT_SUCCESS;
}

