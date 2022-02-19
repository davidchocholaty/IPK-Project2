/**********************************************************/
/*                                                        */
/* File: ipk-sniffer.c                                  */
/* Created: 2022-02-12                                    */
/* Last change: 2022-02-19                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project 2 for course IPK                      */
/* Description: Packet sniffer                            */
/*                                                        */
/**********************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h>
#include <stdint.h>

#include <pcap.h> 

#define SET true
#define UNSET false

#define INIT_OPT(opt)                        \
        opt = &option_default;               \
        opt->interface = &interface_default; \
        opt->port = &port_default;           \
        opt->num = &num_default;

typedef struct interface *interface_t;
typedef struct port *port_t;
typedef struct num *num_t;
typedef struct option *option_t;

struct interface
{
    bool interface_set;
    char *interface_val;
} interface_default =
    {
        .interface_set = UNSET,
        .interface_val = NULL
    };

struct port
{
    bool port_set;
    unsigned short port_val;
} port_default =
    {
        .port_set = UNSET,
        .port_val = 0
    };

struct num
{
    bool num_set;
    unsigned long num_val;
} num_default =
    {
        .num_set = UNSET,
        .num_val = 0L
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
} option_default =
    {
        //.interface = NULL,
        //.port      = NULL,
        //.num       = NULL,
        .tcp_set   = UNSET,
        .udp_set   = UNSET,
        .arp_set   = UNSET,
        .icmp_set  = UNSET,
        .help_set  = UNSET
    };


enum error
{
    NO_ERROR,
    OPT_ERROR,
    UNKNOWN_ERROR
};

void print_error(uint8_t error)
{
    const char *error_msg[] =
    {
        "Exit success",
        "Wrong option",
        "Unknown error"
    };
    
    if(error > UNKNOWN_ERROR)
    {
        error = UNKNOWN_ERROR;
    }

    fprintf(stderr, "Error: %s\n", error_msg[error]);    
}

void print_help (char *prog_name)
{
    printf("usage: %s {-h | --help} [-i <interface> | --interface <interface>] {-p <port>} {[-t|--tcp] [-u|--udp] [--arp] [--icmp]} {-n <num>}\n", prog_name);
    printf("\n");
    printf("-h , --help                                Print this help\n");
    printf("-i <interface>, --interface <interface>    Just one interface to listen on\n");
    printf("-p <port>                                  Filtering on the given interface according to the port\n");
    printf("-t, --tcp                                  Show only TCP packets\n");
    printf("-u, --udp                                  Show only UDP packets\n");
    printf("--arp                                      Show only ARP frames\n");
    printf("--icmp                                     Show only ICMPv4 and ICMPv6 packets\n");    
    printf("-n <num>                                   Number of packets to display\n");
    printf("\n");
}

/*
 * Function to parse long options
 *
 * @param argc      Count of arguments
 * @param argv      Array of arguments
 * @param opt      Struct of options 
 */
void parse_long_opt (int argc,
                     char *argv[],
                     option_t opt)
{
    for (int i = 1; i < argc; i++)
    {
        /* INTERFACE */
        if (strcmp(argv[i], "--interface") == 0)
        {
            opt->interface->interface_set = SET;            
            strcpy(argv[i], "");
            
            /*
             * If this option isnt last argument and
             * following argument isnt option
             */
            if ((i + 1 != argc) && (argv[i+1])[0] != '-')
            {
                /* Following argument is option parameter <interface> */                
                strcpy(opt->interface->interface_val, argv[i+1]);
                strcpy(argv[i+1], "");
            }
        }
        /* TCP */
        else if(strcmp(argv[i], "--tcp") == 0) {
            opt->tcp_set = SET;            
            strcpy(argv[i], "");
        }
        /* UDP */
        else if(strcmp(argv[i], "--udp") == 0) {
            opt->udp_set = SET;            
            strcpy(argv[i], "");
        }
        /* ARP */
        else if(strcmp(argv[i], "--arp") == 0) {
            opt->arp_set = SET;
            strcpy(argv[i], "");
        }
        /* ICMP */
        else if(strcmp(argv[i], "--icmp") == 0) {
            opt->icmp_set = SET;
            strcpy(argv[i], "");
        }
        /* HELP */
        else if(strcmp(argv[i], "--help") == 0) {
            opt->help_set = SET;
            strcpy(argv[i], "");
        }
    }    
}

unsigned short strtous(char *str) {
    for (char *i = str ; *i ; i++) {
        if (!isdigit(*i))
        {
            return 0L;
        }
    }

    unsigned long conv = strtoul(str, NULL, 10);    
    
    return (conv > USHRT_MAX) ? 0L : conv;
}

/*
 * Function to parse short options
 *
 * @param argc      Count of arguments
 * @param argv      Array of arguments
 * @param opt       Struct of options
 * @return          Status of function processing
 */
int parse_short_opt (int argc,
                      char *argv[],
                      option_t opt)
{
    int input_opt;

    /* Colon as first character disable getopt to print errors */
    while ((input_opt = getopt(argc, argv, ":i:p:tun:h")) != -1)
    {
        switch (input_opt)
        {
        case 'i':
            opt->interface->interface_set = SET;

            if (optarg[0] != '-')
            {
                strcpy(opt->interface->interface_val, optarg);
            }            
            
            break;

        case 'p':
            opt->port->port_set = SET;            
            
            if (optarg[0] != '-')
            {
                opt->port->port_val = strtous(optarg);

                if (opt->port->port_val == 0)
                {
                    return EXIT_FAILURE;
                }
            }

            break;

        case 't':
            opt->tcp_set = SET;            
            break;

        case 'u':
            opt->udp_set = SET;            
            break;

        case 'n':
            opt->num->num_set = SET;
            
            if (optarg[0] != '-')
            {
                opt->num->num_val = strtoul(optarg, NULL, 10);

                if (opt->num->num_val == 0L)
                {
                    return EXIT_FAILURE;
                }
            }

            break;

        case 'h':
            opt->help_set = SET;
            break;

        case ':':
            switch (optopt)
            {
            case 'i':
                opt->interface->interface_set = SET;                
                break;
            
            case 'p':
                opt->port->port_set = SET;
                break;

            case 'n':
                opt->num->num_set = SET;
                break;

            default:
                break;
            }

            break;

        case '?':
            return EXIT_FAILURE;

        default:
            break;
        }
    }
    
    return EXIT_SUCCESS;
}

int parse_args (int argc,
                 char *argv[],
                 option_t opt)
{    
    // TODO pokud bude option zadan vickrat
    parse_long_opt(argc, argv, opt);

    return parse_short_opt(argc, argv, opt);    
}

int main (int argc, char *argv[])
{
    option_t opt = NULL;
    
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
        
    }

    return EXIT_SUCCESS;
}
