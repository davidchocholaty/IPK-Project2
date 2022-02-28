/**********************************************************/
/*                                                        */
/* File: option.c                                         */
/* Created: 2022-02-19                                    */
/* Last change: 2022-02-28                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project 2 for course IPK                      */
/* Description: Options handler for packet sniffer        */
/*                                                        */
/**********************************************************/

#include "option.h"

/*
 * Function for print help
 *
 * @param prog_name Name of program
 */
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
 * Function for covert string to unsigned short
 *
 * @param str Input string
 * @return    If string doesnt contain unsigned short number: 0L,
 *            number as unsigned short data type otherwise
 */
unsigned short strtous (char *str)
{
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
 * Function to parse long options
 *
 * @param argc Count of arguments
 * @param argv Array of arguments
 * @param opt  Struct of options 
 */
int parse_long_opt (int argc,
                    char *argv[],
                    option_t opt)
{
    for (int i = 1; i < argc; i++)
    {
        /* INTERFACE */
        if (strcmp(argv[i], "--interface") == 0)
        {
            /* If it is second set of interface option */
            if (opt->interface->interface_set)
            {
            	return EXIT_FAILURE;
            }
            
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
    
    return EXIT_SUCCESS;
}

/*
 * Function to parse short options
 *
 * @param argc Count of arguments
 * @param argv Array of arguments
 * @param opt  Struct of options
 * @return     Status of function processing
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
            /* If it is second set of interface option */        
            if (opt->interface->interface_set)
            {
            	return EXIT_FAILURE;
            }
            
            opt->interface->interface_set = SET;

            if (optarg[0] != '-')
            {
                strcpy(opt->interface->interface_val, optarg);
            }            
            
            break;

        case 'p':
            /* If it is second set of port option */        
            if (opt->port->port_set)
            {
            	return EXIT_FAILURE;
            }
        
            opt->port->port_set = SET;            
            
            if (optarg[0] != '-')
            {
                opt->port->port_val = strtous(optarg);

		/* If it isnt possible to convert to unsigned short */
                if (opt->port->port_val == 0)
                {
                    return EXIT_FAILURE;
                }
            }
            else
            {
                return EXIT_FAILURE;
            }

            break;

        case 't':
            opt->tcp_set = SET;            
            break;

        case 'u':
            opt->udp_set = SET;            
            break;

        case 'n':
            if (opt->num->num_set)
            {
            	return EXIT_FAILURE;
            }
        
            opt->num->num_set = SET;
            
            if (optarg[0] != '-')
            {
                opt->num->num_val = strtoul(optarg, NULL, 10);

                if (opt->num->num_val == 0L)
                {
                    return EXIT_FAILURE;
                }
            }
            else
            {
                return EXIT_FAILURE;
            }

            break;

        case 'h':
            opt->help_set = SET;
            break;

        case ':':
            if (optopt == 'i')
            {
                /* If it is second set of interface option */            
            	if (opt->interface->interface_set)
            	{
         	    return EXIT_FAILURE;
            	}
            
		opt->interface->interface_set = SET;
		break;
            }
            
            return EXIT_FAILURE;

        case '?':
            return EXIT_FAILURE;

        default:
            break;
        }
    }
    
    return EXIT_SUCCESS;
}

/*
 * Main function for parsing arguments
 *
 * @param argc Count of arguments
 * @param argv Arguments
 * @param opt  Pointer to options storage
 * @return     Status of parse_short_opt function processing
 */
int parse_args (int argc,
                char *argv[],
                option_t opt)
{
    if (parse_long_opt(argc, argv, opt) != EXIT_SUCCESS)
    {
    	return EXIT_FAILURE;
    }

    return parse_short_opt(argc, argv, opt);
}

