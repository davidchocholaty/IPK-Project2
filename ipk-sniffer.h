/**********************************************************/
/*                                                        */
/* File: ipk-sniffer.h                                    */
/* Created: 2022-02-12                                    */
/* Last change: 2022-02-18                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project 2 for course IPK                      */
/* Description: Header file for packet sniffer            */
/*                                                        */
/**********************************************************/

#ifndef IPK_SNIFFER_H
#define IPK_SNIFFER_H

/****** INCLUDES ******/

#include <signal.h>
#include <pcap.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include "error.h"
#include "option.h"

/***** DEFINITIONS ****/

/* 
 * Next macro is taken from following source:
 * Source: https://stackoverflow.com/questions/3599160/how-can-i-suppress-unused-parameter-warnings-in-c
 * Authors of answer:
 * - mtvec (https://stackoverflow.com/users/248066/mtvec), answered Aug 30, 2010 at 9:16
 * - SO Stinks (https://stackoverflow.com/users/2577374/so-stinks), edited Mar 20, 2013 at 8:20
 */
#define UNUSED(x) (void)(x)

#define IPv4 false
#define IPv6 true

#define PORT_FILTER_MAX_LEN 12
#define FILTER_MAX_LEN 90

#define UDP_SIZE 8

#define IPv6_PACKET_TYPE 34525

#define ADD_TCP_FILTER(opt, filter, port_filter, port_is_set)      \
        strcat(filter, "tcp");                                     \
                                                                   \
        if (port_is_set)                                           \
        {                                                          \
            sprintf(port_filter, " port %d", opt->port->port_val); \
            strcat(filter, port_filter);                           \
        }

#define ADD_UDP_FILTER(opt, filter, port_filter, port_is_set)      \
        if(strcmp(filter, "") != 0)                                \
        {                                                          \
            strcat(filter, " or ");                                \
        }                                                          \
                                                                   \
        strcat(filter, "udp");                                     \
                                                                   \
        if (port_is_set)                                           \
        {                                                          \
            sprintf(port_filter, " port %d", opt->port->port_val); \
            strcat(filter, port_filter);                           \
        }

#define ADD_ICMP_FILTER(opt, filter, port_filter, port_is_set)     \
        if(strcmp(filter, "") != 0)                                \
        {                                                          \
            strcat(filter, " or ");                                \
        }                                                          \
                                                                   \
        strcat(filter, "icmp");                                    \
                                                                   \
        strcat(filter, " or icmp6");

#define ADD_ARP_FILTER(opt, filter, port_filter, port_is_set)      \
        if(strcmp(filter, "") != 0)                                \
        {                                                          \
            strcat(filter, " or ");                                \
        }                                                          \
                                                                   \
        strcat(filter, "arp");

#endif // IPK_SNIFFER_H
