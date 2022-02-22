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

void handle_ipv4_packet (const u_char *packet_ptr)
{
    struct ip *ip_header;    
    struct tcphdr* tcp_header;
    struct udphdr* udp_header;
    struct icmp* icmp_header;
    struct arphdr* arp_header;
    
    //TODO velikost
    char src_ip[256];
    char dst_ip[256];

    /* Skip the datalink layer header and get the IP header fields */
    packet_ptr += link_header_len;
    ip_header = (struct ip*)packet_ptr;
    strcpy(src_ip, inet_ntoa(ip_header->ip_src));
    strcpy(dst_ip, inet_ntoa(ip_header->ip_dst));

    /* Advance to the transport layer header */ 
    packet_ptr += 4*ip_header->ip_hl;

    /* Parse and display the fields based on the type of hearder: tcp, udp, icmp or arp */
    switch (ip_header->ip_p)
    {
    /* TCP    */
    case IPPROTO_TCP:
        tcp_header = (struct tcphdr*)packet_ptr;
        //TODO print
        /* TODO smazat */
        tcp_header = tcp_header;
        break;
    
    /* UDP    */
    case IPPROTO_UDP:
        udp_header = (struct udphdr*)packet_ptr;
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

void handle_ipv6_packet (const u_char *packet_ptr)
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
    bool ip_flag = IPv4;

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
        ip_flag = IPv6;
    }

    // TODO time


    /*
        TODO smazat
     */
    user = user;
    packet_header = packet_header;
    ip_flag = ip_flag;


















    /*
    struct ip* iphdr;
    struct icmp* icmphdr;
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;
    char iphdrInfo[256];
    char srcip[256];
    char dstip[256];
 
     // Skip the datalink layer header and get the IP header fields.
    packet_ptr += link_header_len;
    iphdr = (struct ip*)packet_ptr;
    strcpy(srcip, inet_ntoa(iphdr->ip_src));
    strcpy(dstip, inet_ntoa(iphdr->ip_dst));
    sprintf(iphdrInfo, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
            ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,
            4*iphdr->ip_hl, ntohs(iphdr->ip_len));
 
    // Advance to the transport layer header then parse and display
    // the fields based on the type of hearder: tcp, udp or icmp.
    packet_ptr += 4*iphdr->ip_hl;

    switch (iphdr->ip_p)
    {
    case IPPROTO_TCP:
        tcphdr = (struct tcphdr*)packet_ptr;
        printf("TCP  %s:%d -> %s:%d\n", srcip, ntohs(tcphdr->th_sport),
               dstip, ntohs(tcphdr->th_dport));
        printf("%s\n", iphdrInfo);
        printf("%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
               (tcphdr->th_flags & TH_URG ? 'U' : '*'),
               (tcphdr->th_flags & TH_ACK ? 'A' : '*'),
               (tcphdr->th_flags & TH_PUSH ? 'P' : '*'),
               (tcphdr->th_flags & TH_RST ? 'R' : '*'),
               (tcphdr->th_flags & TH_SYN ? 'S' : '*'),
               (tcphdr->th_flags & TH_SYN ? 'F' : '*'),
               ntohl(tcphdr->th_seq), ntohl(tcphdr->th_ack),
               ntohs(tcphdr->th_win), 4*tcphdr->th_off);
        printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
        packets += 1;
        break;
 
    case IPPROTO_UDP:
        udphdr = (struct udphdr*)packet_ptr;
        printf("UDP  %s:%d -> %s:%d\n", srcip, ntohs(udphdr->uh_sport),
               dstip, ntohs(udphdr->uh_dport));
        printf("%s\n", iphdrInfo);
        printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
        packets += 1;
        break;
 
    case IPPROTO_ICMP:
        icmphdr = (struct icmp*)packet_ptr;
        printf("ICMP %s -> %s\n", srcip, dstip);
        printf("%s\n", iphdrInfo);
        printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->icmp_type, icmphdr->icmp_code,
               ntohs(icmphdr->icmp_hun.ih_idseq.icd_id), ntohs(icmphdr->icmp_hun.ih_idseq.icd_seq));
        printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
        packets += 1;
        break;
    }
    */
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
