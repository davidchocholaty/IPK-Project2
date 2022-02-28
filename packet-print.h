/**********************************************************/
/*                                                        */
/* File: packet-print.h                                   */
/* Created: 2022-02-27                                    */
/* Last change: 2022-02-28                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project 2 for course IPK                      */
/* Description: Header file for packet print              */
/*                                                        */
/**********************************************************/

#ifndef PACKET_PRINT_H
#define PACKET_PRINT_H

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

void print_tcp_packet (const u_char *packet_ptr, int size);
void print_udp_packet (const u_char *packet_ptr, int size);
void print_icmp_packet (const u_char *packet_ptr, int size);
void print_arp_frame (const u_char *packet_ptr, int size);
void print_ipv6_tcp_packet (const u_char *packet_ptr, int size);
void print_ipv6_udp_packet (const u_char *packet_ptr, int size);
void print_ipv6_icmp_packet (const u_char *packet_ptr, int size);
int print_timestamp (const struct timeval *timestamp);
void print_interfaces ();

#endif // PACKET_PRINT_H
