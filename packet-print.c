/**********************************************************/
/*                                                        */
/* File: packet-print.c                                   */
/* Created: 2022-02-27                                    */
/* Last change: 2022-02-27                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project 2 for course IPK                      */
/* Description: Packet sniffer                            */
/*                                                        */
/**********************************************************/

#include "packet-print.h"

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

/* https://gist.github.com/jedisct1/b7812ae9b4850e0053a21c922ed3e9dc */
int print_timestamp (const struct timeval *timestamp)
{
	struct tm *tm;
   	int off_sign;
	int off;
	
	if ((tm = localtime(&timestamp->tv_sec)) == NULL)
	{
		return EXIT_FAILURE;
    	}
    
	off_sign = '+';
    	off = (int) tm->tm_gmtoff;
    
	if (tm->tm_gmtoff < 0)
	{
	        off_sign = '-';
        	off = -off;
    	}
	
	printf("timestamp: %d-%02d-%02dT%02d:%02d:%02d.%ld%c%02d:%02d\n",
	        tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
	        tm->tm_hour, tm->tm_min, tm->tm_sec, timestamp->tv_usec,
	        off_sign, off / 3600, off % 3600);

	return EXIT_SUCCESS;
}

void print_interfaces ()
{
	char err_buf[PCAP_ERRBUF_SIZE];
	pcap_if_t *interfaces;
	
	if (pcap_findalldevs(&interfaces, err_buf) < 0)
	{
		printf("Error in pcap_findalldevs(): %s", err_buf);
        exit(EXIT_FAILURE);
	}
	
	for (pcap_if_t *i = interfaces; i; i = i->next)
	{
		printf("%s\n", i->name);
	}
}

