/**********************************************************/
/*                                                        */
/* File: option.h                                         */
/* Created: 2022-02-19                                    */
/* Last change: 2022-02-19                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project 2 for course IPK                      */
/* Description: Header file for options handler           */
/*                                                        */
/**********************************************************/

#ifndef IPK_SNIFFER_OPTION_H
#define IPK_SNIFFER_OPTION_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>

#define SET   true
#define UNSET false

#define INT_SIZE 256

#define INIT_OPT(opt)                        \
        struct interface interface_default = \
        {                                    \
            .interface_set = UNSET,          \
            .interface_val = ""              \
        };                                   \
                                             \
        struct port port_default =           \
        {                                    \
            .port_set = UNSET,               \
            .port_val = 0                    \
        };                                   \
                                             \
        struct num num_default =             \
        {                                    \
            .num_set = UNSET,                \
            .num_val = 0L                    \
        };                                   \
                                             \
        struct option option_default =       \
        {                                    \
            .interface = NULL,               \
            .port      = NULL,               \
            .num       = NULL,               \
            .tcp_set   = UNSET,              \
            .udp_set   = UNSET,              \
            .arp_set   = UNSET,              \
            .icmp_set  = UNSET,              \
            .help_set  = UNSET               \
        };                                   \
                                             \
        opt            = &option_default;    \
        opt->interface = &interface_default; \
        opt->port      = &port_default;      \
        opt->num       = &num_default;

typedef struct interface *interface_t;
typedef struct port *port_t;
typedef struct num *num_t;
typedef struct option *option_t;

struct interface
{
    bool interface_set;
    char interface_val[INT_SIZE];
};

struct port
{
    bool port_set;
    unsigned short port_val;
};

struct num
{
    bool num_set;
    unsigned long num_val;
};

struct option
{    
    interface_t interface;
    port_t port;
    num_t num;
    bool tcp_set;
    bool udp_set;
    bool arp_set;
    bool icmp_set;
    bool help_set;
};

void print_help (char *prog_name);
int parse_args (int argc, char *argv[], option_t opt);

#endif // IPK_SNIFFER_OPTION_H
