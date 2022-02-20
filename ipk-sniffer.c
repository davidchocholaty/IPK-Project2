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
        is_valid = true
    }
    
    return is_valid;
}

pcap_t *create_pcap_handle (char *device, char *filter)
{
    char err_buf[PCAP_err_buf_SIZE];
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

void packet_handler(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr)
{
    struct ip* iphdr;
    struct icmp* icmphdr;
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;
    char iphdrInfo[256];
    char srcip[256];
    char dstip[256];
 
     // Skip the datalink layer header and get the IP header fields.
    packetptr += link_header_len;
    iphdr = (struct ip*)packetptr;
    strcpy(srcip, inet_ntoa(iphdr->ip_src));
    strcpy(dstip, inet_ntoa(iphdr->ip_dst));
    sprintf(iphdrInfo, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
            ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,
            4*iphdr->ip_hl, ntohs(iphdr->ip_len));
 
    // Advance to the transport layer header then parse and display
    // the fields based on the type of hearder: tcp, udp or icmp.
    packetptr += 4*iphdr->ip_hl;
    switch (iphdr->ip_p)
    {
    case IPPROTO_TCP:
        tcphdr = (struct tcphdr*)packetptr;
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
        udphdr = (struct udphdr*)packetptr;
        printf("UDP  %s:%d -> %s:%d\n", srcip, ntohs(udphdr->uh_sport),
               dstip, ntohs(udphdr->uh_dport));
        printf("%s\n", iphdrInfo);
        printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
        packets += 1;
        break;
 
    case IPPROTO_ICMP:
        icmphdr = (struct icmp*)packetptr;
        printf("ICMP %s -> %s\n", srcip, dstip);
        printf("%s\n", iphdrInfo);
        printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->icmp_type, icmphdr->icmp_code,
               ntohs(icmphdr->icmp_hun.ih_idseq.icd_id), ntohs(icmphdr->icmp_hun.ih_idseq.icd_seq));
        printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
        packets += 1;
        break;
    }
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
    char *filter = NULL;

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

        // filter
        // tcp port <port> or udp port <port> or icmp port <port> or arp port <port>

        //TODO s options
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
        if (pcap_loop(handle, /*TODO parametr n*/, packet_handler, (u_char*)NULL) < 0) {
            fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
            return EXIT_FAILURE;
        }
        
        stop_capture();        
    }

    return EXIT_SUCCESS;
}
