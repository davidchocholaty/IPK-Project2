/**********************************************************/
/*                                                        */
/* File: ipk-sniffer.c                                    */
/* Created: 2022-02-12                                    */
/* Last change: 2022-02-19                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project 2 for course IPK                      */
/* Description: Packet sniffer                            */
/*                                                        */
/**********************************************************/

/*
 * Links:
 * https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/
 * https://github.com/yuan901202/vuw_nwen302_ethernet_packet_sniffer/blob/master/eps.c
 * https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
 */

#include "ipk-sniffer.h"

pcap_t *handle;
int link_header_len;
int packets;

bool valid_interface (option_t opt)
{       
    bool is_valid = false;
    bool is_set = opt->interface->interface_set;
    char *val = opt->interface->interface_val;

    if (is_set && val != NULL)
    {
        is_valid = true;
    }
    
    return is_valid;
}

void create_filter (option_t opt, char *filter)
{
    // tcp port <port> or udp port <port> or icmp port <port> or arp port <port>
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
    if (opt->tcp_set)
    {
        ADD_ARP_FILTER(opt, filter, port_filter, port_is_set);
    }    
}

pcap_t *create_pcap_handle (char *device, char *filter)
{
    char err_buf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    struct bpf_program bpf;
    bpf_u_int32 netmask;
    bpf_u_int32 src_ip;    

    /* Get network device source IP address and netmask */
    if (pcap_lookupnet(device, &src_ip, &netmask, err_buf) == PCAP_ERROR)
    {
        fprintf(stderr, "pcap_lookupnet: %s\n", err_buf);
        return NULL;
    }

    /* Open the device for live capture */
    if ((handle = pcap_open_live(device, BUFSIZ, 1, 1000, err_buf)) == NULL)
    {
        fprintf(stderr, "pcap_open_live(): %s\n", err_buf);
        return NULL;
    }

    /* Convert the packet filter epxression into a packet filter binary */
    if (pcap_compile(handle, &bpf, filter, 0, netmask) == PCAP_ERROR)
    {
        fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handle));
        return NULL;
    }

    /* Bind the packet filter to the libpcap handle */
    if (pcap_setfilter(handle, &bpf) == PCAP_ERROR)
    {
        fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(handle));
        return NULL;
    }

    return handle;    
}

void get_link_header_len(pcap_t* handle)
{
    int link_type;
 
    /* Determine the datalink layer type */
    if ((link_type = pcap_datalink(handle)) == PCAP_ERROR) {
        fprintf(stderr, "pcap_datalink(): %s\n", pcap_geterr(handle));
        return;
    }
 
    /* Set the datalink layer header size */
    switch (link_type)
    {
    case DLT_NULL:
        link_header_len = DLT_NULL_LEN;
        break;
 
    case DLT_EN10MB:
        link_header_len = DLT_EN10MB_LEN;
        break;
 
    case DLT_LINUX_SLL:
        link_header_len = DLT_LINUX_SLL_LEN;
        break;

    case DLT_SLIP:
    case DLT_PPP:
        link_header_len = DLT_SLIP_PPP_LEN;
        break;
 
    default:
        printf("Unsupported datalink (%d)\n", link_type);
        link_header_len = 0;
    }
}
/*
void print_hex (u_char *packet_data, int start, int end)
{
    printf(" ");

    for (int i = start; i < end; i++)
    {
        printf("%02x ", packet_data[i]);
    }
    
    int rest = end - start;

    if (rest < 16)
    {
        for (int i = 0; i < 16; i++)
        {
            printf("   ");
        }        
    }

    printf(" ");
}

void print_ascii (u_char *packet_data, int start, int end)
{
    for (int i = start; i < end; i++)
    {
        if (isprint(packet_data[i]))
        {
            printf("%c", packet_data[i]);
        }
        else
        {
            print(".");
        }
    }
}

void print_data (u_char *packet_data, int packet_size)
{
    if (packet_size == 0)
    {
        // TODO
    }
    
    int i = 0;

    const int S = 16;

    for (i = 0; i <= packet_size - S; i+=S)
    {
        printf("0x%04x ", i);
        print_hex(packet_data, i, S + i);
        print_ascii(packet_data, i, S + i);
        printf("\n");
    }
}
*/

/* https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/ */
void print_data (const u_char *packet_data, int size)
{
    int i, j;

    for (i = 0; i < size; i++)
    {
        //if one line of hex printing is complete...
        if ((i != 0) && (i % 16 == 0))
        {
            printf("         ");

            for (j = i - 16; j < i; j++)
            {
                if (isprint(packet_data[j]))
                {
                    printf("%c", (unsigned char) packet_data[i]);
                }
                else
                {
                    printf(".");
                }                
            }
            printf("\n");
        }
        
        if (i % 16 == 0) printf("   ");
            printf(" %02X", (unsigned char)packet_data[i]);

        if (i == size - 1) // print the last spaces
        {
            for (j = 0; j < 15 - i%16; j++)
            {
                printf("   "); //extra spaces
            }
            
            printf("         ");

            for (j = i - i%16; j <= i; j++)
            {
                if (isprint(packet_data[j]))
                {
                    printf("%c", (unsigned char) packet_data[j]);
                }
                else
                {
                    printf(".");
                }                           
            }
            printf("\n" );
        }
    }
}

void handle_ipv4_packet (const u_char *packet_ptr, const struct pcap_pkthdr *packet_header)
{
    /*
        TCP
        ---------

        size_ip = 4 * ip_header->ip_hl
        size_tcp = 4 * tcp_header->doff

        (link_header_length + size_ip + size_tcp)

        UDP
        ---------

        size_ip = 4 * ip_header->ip_hl
        SIZE_UDP = 8
        (link_header_length + size_ip + SIZE_UDP)
    */
    struct ip *ip_header;    
    struct tcphdr* tcp_header;
    struct udphdr* udp_header;
    struct icmp* icmp_header;
    struct arphdr* arp_header;    
    
    //TODO velikost
    char src_ip[256];
    char dst_ip[256];

    u_int ip_size;
    u_int tcp_size;

    /* Skip the datalink layer header and get the IP header fields */
    packet_ptr += link_header_len;
    ip_header = (struct ip*)packet_ptr;
    strcpy(src_ip, inet_ntoa(ip_header->ip_src));
    strcpy(dst_ip, inet_ntoa(ip_header->ip_dst));

    /* Advance to the transport layer header */
    ip_size = 4*ip_header->ip_hl;
    packet_ptr += ip_size;

    /* Parse and display the fields based on the type of hearder: tcp, udp, icmp or arp */
    switch (ip_header->ip_p)
    {
    /* TCP    */
    case IPPROTO_TCP:
        tcp_header = (struct tcphdr*)packet_ptr;
        tcp_size = 4 * tcp_header->doff;

        //(link_header_length + ip_size + tcp_size)


        //TODO print
        /* TODO smazat */        
        packet_header = packet_header;

        break;
    
    /* UDP    */
    case IPPROTO_UDP:
        udp_header = (struct udphdr*)packet_ptr;
    
        //(link_header_length + ip_size + UDP_SIZE)

        //TODO print
        /* TODO smazat */
        udp_header = udp_header;
        break;

    /* ICMPv4 */
    case IPPROTO_ICMP:
        icmp_header = (struct icmp*)packet_ptr;
        //TODO print
        /* TODO smazat */
        icmp_header = icmp_header;
        break;

    /* ARP    */    
    default:
        arp_header = (struct arphdr*)packet_ptr;
        //TODO print
        /* TODO smazat */
        arp_header = arp_header;
        break;
    }
}

void handle_ipv6_packet (const u_char *packet_ptr, const struct pcap_pkthdr *packet_header)
{
    struct ip6_hdr *ipv6_header;
    struct tcphdr* tcp_header;
    struct udphdr* udp_header;
    struct icmp* icmp_header;
    
    //TODO velikost
    char ipv6_src_ip[256];
    char ipv6_dst_ip[256];

    /* Skip the datalink layer header and get the IP header fields */
    packet_ptr += link_header_len;
    ipv6_header = (struct ip6_hdr*)packet_ptr;

    /* Get ipv6 header */
    inet_ntop(AF_INET6, &(ipv6_header->ip6_src), ipv6_src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), ipv6_dst_ip, INET6_ADDRSTRLEN);

    int next_header = ipv6_header->ip6_nxt;

    /*
    TODO jestli jeste nejake to pricitani 40
    */

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

    switch (next_header)
    {
    /* TCP                 */
    case IPPROTO_TCP:
        tcp_header = (struct tcphdr*)packet_ptr;
        //TODO print
        /* TODO smazat */
        tcp_header = tcp_header;
        packet_header = packet_header;

        break;

    /* UDP                 */
    case IPPROTO_UDP:
        udp_header = (struct udphdr*)packet_ptr;
        //TODO print
        /* TODO smazat */
        udp_header = udp_header;
        break;

    /* ICMPv6              */
    case IPPROTO_ICMPV6:
        icmp_header = (struct icmp*)packet_ptr;
        //TODO print
        /* TODO smazat */
        icmp_header = icmp_header;
        break;
    
    default:
        break;
    }
}

void packet_handler(u_char *user, const struct pcap_pkthdr *packet_header, const u_char *packet_ptr)
{    
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

    /* Otherwise it packet type IPv4 -> default value of ip_flag */
    if (packet_type == IPv6_PACKET_TYPE)
    {
        handle_ipv6_packet(packet_ptr, packet_header);
    }
    else
    {
        handle_ipv4_packet(packet_ptr, packet_header);
    }

    // TODO time


    /*
        TODO smazat
     */
    user = user;
    packet_header = packet_header;
}

void stop_capture()
{
    struct pcap_stat stats;

    if (pcap_stats(handle, &stats) >= 0)
    {
        printf("%d packets received\n", stats.ps_recv);
        printf("%d packets dropped\n\n", stats.ps_drop);
    }

    pcap_close(handle);

    exit(EXIT_SUCCESS);
}

int main (int argc, char *argv[])
{
    option_t opt = NULL;
    char *device = NULL;
    char filter[FILTER_MAX_LEN];
    unsigned long packet_cnt;

    INIT_OPT(opt);    

    if (parse_args(argc, argv, opt) != EXIT_SUCCESS)
    {
        print_error(OPT_ERROR);
        return EXIT_FAILURE;
    }

    if (opt->help_set == SET)
    {
        print_help(argv[0]);    
    }
    else
    {
        if (!valid_interface(opt))
        {
            // TODO vyprintit vsechny rozhrani
            // TODO jestli EXIT_SUCCESS nebo EXIT_FAILURE
            return EXIT_SUCCESS;
        }

        signal(SIGINT, stop_capture);
        signal(SIGTERM, stop_capture);
        signal(SIGQUIT, stop_capture);
        
        device = opt->interface->interface_val;
        packet_cnt = (opt->num->num_set) ? opt->num->num_val : 0L;

        create_filter(opt, filter);
        
        handle = create_pcap_handle(device, filter);

        if (handle == NULL) {
            return EXIT_FAILURE;
        }

        /* Get the type of link layer */
        get_link_header_len(handle);
        if (link_header_len == 0) {
            return EXIT_FAILURE;
        }

        /* Start the packet capture with a set count or continually if the count is 0 */
        if (pcap_loop(handle, packet_cnt, packet_handler, (u_char*)NULL) < 0) {
            fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
            return EXIT_FAILURE;
        }
        
        stop_capture();        
    }

    return EXIT_SUCCESS;
}
