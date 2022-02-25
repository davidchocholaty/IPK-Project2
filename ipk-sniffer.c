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
    // tcp port <port> or udp port <port> or icmp port <port> or icmp6 port <port> or arp port <port>
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
}

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
    if (pcap_compile(handle, &bpf, (char *)filter, 0, netmask) == PCAP_ERROR)
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

/* https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/ */
void print_data (const u_char *packet_data, int size)
{

    int i, j;

    for (i = 0; i < size; i++)
    {
        //if one line of hex printing is complete...
        if ((i != 0) && (i % 16 == 0))
        {
        	/* Space between hexa and ascii */
			printf(" ");

            for (j = i - 16; j < i; j++)
            {
            	/* Space at start and in the middle of ascii values */
            	if (j % 8 == 0)
            	{
            		printf(" ");
            	}
            	
            	/* Print ascii value */
                if (isprint(packet_data[j]))
                {
                    printf("%c", (unsigned char) packet_data[j]);
                }
                else
                {
                    printf(".");
                }                
            }
            printf("\n");
        }
        
        /* Print offset */
        if (i % 16 == 0)
        {
	       	printf("0x%03x0: ", i/16);
        }
		/* Print space in the middle of hexa values */
        else if (i % 8 == 0)
        {
			printf(" ");
        }                
        
        /* Print hexa value */
        printf(" %02x", (unsigned char)packet_data[i]);

		/* Print the last spaces */
        if (i == size - 1)
        {
            for (j = 0; j < 15 - i%16; j++)
            {
            	if ((i + j) % 8 == 0)
            	{
            		printf(" ");
            	}
            	
	            /* Extra spaces */
                printf("   ");
            }
            
            /* Space between hexa and ascii values at last row */
			printf(" ");

            for (j = i - i%16; j <= i; j++)
            {	            
				/* Space at start and in the middle of ascii values at last row */
            	if (j % 8 == 0)
            	{
            		printf(" ");
            	}
            	
            	/* Print ascii values at last row */
                if (isprint(packet_data[j]))
                {
                    printf("%c", (unsigned char) packet_data[j]);
                }
                else
                {
                    printf(".");
                }                           
            }
            
            printf("\n\n\n");
        }
    }
}

void print_macs (const u_char *packet_ptr)
{
	struct ethhdr *eth = (struct ethhdr *)packet_ptr;
	
	printf("src MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
	       eth->h_source[0], eth->h_source[1], eth->h_source[2],
	       eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	printf("dst MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
	       eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
	       eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
}

void print_frame_length (int size)
{
	printf("frame length: %d bytes\n", size);
}

void print_ips (const u_char *packet_ptr)
{
	struct iphdr *ip_header = (struct iphdr *)(packet_ptr + sizeof(struct ethhdr));
	struct sockaddr_in source, dest;
	
	source.sin_addr.s_addr = ip_header->saddr;
	dest.sin_addr.s_addr = ip_header->daddr;

	printf("src IP: %s\n" , inet_ntoa(source.sin_addr));
	printf("dst IP: %s\n" , inet_ntoa(dest.sin_addr));
}

void print_ipv6_ips (const u_char *packet_ptr)
{
	//TODO
	struct ip6_hdr *ipv6_header = (struct ip6_hdr *)(packet_ptr + sizeof(struct ethhdr));

	char ipv6_src_ip[INET6_ADDRSTRLEN];
	char ipv6_dst_ip[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, &(ipv6_header->ip6_src), ipv6_src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), ipv6_dst_ip, INET6_ADDRSTRLEN);
	
	printf("src IP: %s\n", ipv6_src_ip);
	printf("dst IP: %s\n", ipv6_dst_ip);
}

void print_tcp_ports (const u_char *packet_ptr)
{
	struct iphdr *ip_header = (struct iphdr *)(packet_ptr + sizeof(struct ethhdr));
	unsigned short ip_header_len = 4*ip_header->ihl;	
	
	struct tcphdr *tcp_header = (struct tcphdr *)(packet_ptr + ip_header_len + sizeof(struct ethhdr));

	printf("src port: %u\n", ntohs(tcp_header->source));
	printf("dst port: %u\n", ntohs(tcp_header->dest));
	printf("\n");
}

void print_udp_ports (const u_char *packet_ptr)
{
	struct iphdr *ip_header = (struct iphdr *)(packet_ptr + sizeof(struct ethhdr));
	unsigned short ip_header_len = 4*ip_header->ihl;
	
	struct udphdr *udp_header = (struct udphdr *)(packet_ptr + ip_header_len + sizeof(struct ethhdr));
	
	printf("src port: %u\n", ntohs(udp_header->source));
	printf("dst port: %u\n", ntohs(udp_header->dest));
}

void print_ipv6_tcp_ports (const u_char *packet_ptr)
{
	struct iphdr *ip_header = (struct iphdr *)(packet_ptr + sizeof(struct ethhdr));
	unsigned short ip_header_len = 4*ip_header->ihl + sizeof(struct ip6_hdr);
	
	struct tcphdr *tcp_header = (struct tcphdr *)(packet_ptr + ip_header_len + sizeof(struct ethhdr));

	printf("src port: %u\n", ntohs(tcp_header->source));
	printf("dst port: %u\n", ntohs(tcp_header->dest));
	printf("\n");	
}

void print_ipv6_udp_ports (const u_char *packet_ptr)
{
	struct iphdr *ip_header = (struct iphdr *)(packet_ptr + sizeof(struct ethhdr));
	unsigned short ip_header_len = 4*ip_header->ihl + sizeof(struct ip6_hdr);
	
	struct udphdr *udp_header = (struct udphdr *)(packet_ptr + ip_header_len + sizeof(struct ethhdr));
	
	printf("src port: %u\n", ntohs(udp_header->source));
	printf("dst port: %u\n", ntohs(udp_header->dest));	
}

void print_vertical_indent()
{
	printf("\n");
}

void print_tcp_packet (const u_char *packet_ptr, int size)
{
	print_macs(packet_ptr);
	print_frame_length(size);
	print_ips(packet_ptr);
	print_tcp_ports(packet_ptr);
	print_vertical_indent();
	print_data(packet_ptr, size);
}

void print_udp_packet (const u_char *packet_ptr, int size)
{
	print_macs(packet_ptr);
	print_frame_length(size);
	print_ips(packet_ptr);
	print_udp_ports(packet_ptr);
	print_vertical_indent();
	print_data(packet_ptr, size);
}

void print_icmp_packet (const u_char *packet_ptr, int size)
{
	print_macs(packet_ptr);
	print_frame_length(size);
	print_ips(packet_ptr);
	print_vertical_indent();
	print_data(packet_ptr, size);
}

void print_arp_frame (const u_char *packet_ptr, int size)
{
	print_macs(packet_ptr);
	print_frame_length(size);
	print_vertical_indent();
	print_data(packet_ptr, size);		
}

void print_ipv6_tcp_packet (const u_char *packet_ptr, int size)
{
	print_macs(packet_ptr);
	print_frame_length(size);
	print_ipv6_ips(packet_ptr);	
	print_ipv6_tcp_ports(packet_ptr);
	print_vertical_indent();
	print_data(packet_ptr, size);
}

void print_ipv6_udp_packet (const u_char *packet_ptr, int size)
{
	print_macs(packet_ptr);
	print_frame_length(size);
	print_ipv6_ips(packet_ptr);	
	print_ipv6_udp_ports(packet_ptr);
	print_vertical_indent();
	print_data(packet_ptr, size);
}

void print_ipv6_icmp_packet (const u_char *packet_ptr, int size)
{
	print_macs(packet_ptr);
	print_frame_length(size);
	print_ipv6_ips(packet_ptr);
	print_vertical_indent();
	print_data(packet_ptr, size);
}

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

/* https://gist.github.com/jedisct1/b7812ae9b4850e0053a21c922ed3e9dc */
int print_timestamp (const struct timeval *timestamp)
{
	struct tm *tm;
   	int off_sign;
	int off;
	
	if ((tm = localtime(&timestamp->tv_sec)) == NULL) {
		return EXIT_FAILURE;
    }
    
	off_sign = '+';
    off = (int) tm->tm_gmtoff;
    
	if (tm->tm_gmtoff < 0) {
        off_sign = '-';
        off = -off;
    }
	
	printf("timestamp: %d-%02d-%02dT%02d:%02d:%02d.%ld%c%02d:%02d\n",
       tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
       tm->tm_hour, tm->tm_min, tm->tm_sec, timestamp->tv_usec,
       off_sign, off / 3600, off % 3600);

	return EXIT_SUCCESS;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *packet_header, const u_char *packet_ptr)
{    

	/* For compiler to dont show warning about unused variable */
	//TODO smazat
    user = user;
    
	/* Timestamp */
	if (print_timestamp(&(packet_header->ts)) != EXIT_SUCCESS)
	{
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

void stop_capture()
{
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
