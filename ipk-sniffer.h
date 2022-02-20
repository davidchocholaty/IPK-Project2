/**********************************************************/
/*                                                        */
/* File: ipk-sniffer.h                                    */
/* Created: 2022-02-12                                    */
/* Last change: 2022-02-19                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project 2 for course IPK                      */
/* Description: Header file for packet sniffer            */
/*                                                        */
/**********************************************************/

#ifndef IPK_SNIFFER_H
#define IPK_SNIFFER_H

#include <signal.h>
#include <time.h>

#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include "error.h"
#include "option.h"

#define DLT_NULL_LEN       4
#define DLT_EN10MB_LEN    14
#define DLT_LINUX_SLL_LEN 16
#define DLT_SLIP_PPP_LEN  24

#define IPv4 false
#define IPv6 true

#define IPv6_PACKET_TYPE 34525

#define ADD_TCP_FILTER(opt, filter, port_is_set)             \
        strcat(filter, "tcp");                               \
                                                             \
        if (port_is_set)                                     \
        {                                                    \
            strcat(filter, " port %d", opt->port->port_val); \
        }

#define ADD_UDP_FILTER(opt, filter, port_is_set)             \
        if(strcmp(filter, "") != 0)                          \
        {                                                    \
            strcat(filter, " or ");                          \
        }                                                    \
                                                             \
        strcat(filter, "udp");                               \
                                                             \        
        if (port_is_set)                                     \
        {                                                    \
            strcat(filter, " port %d", opt->port->port_val); \
        }

#define ADD_ICMP_FILTER(opt, filter, port_is_set)            \
        if(strcmp(filter, "") != 0)                          \
        {                                                    \
            strcat(filter, " or ");                          \
        }                                                    \
                                                             \
        strcat(filter, "icmp");                              \
                                                             \        
        if (port_is_set)                                     \
        {                                                    \
            strcat(filter, " port %d", opt->port->port_val); \
        }

#define ADD_ARP_FILTER(opt, filter, port_is_set)             \
        if(strcmp(filter, "") != 0)                          \
        {                                                    \
            strcat(filter, " or ");                          \
        }                                                    \
                                                             \
        strcat(filter, "arp");                               \
                                                             \        
        if (port_is_set)                                     \
        {                                                    \
            strcat(filter, " port %d", opt->port->port_val); \
        }
#endif // IPK_SNIFFER_H
