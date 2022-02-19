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

/*
pcap_t *create_pcap_handle (char *device, char *filter)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    pcap_if_t *devices = NULL;
    struct bpf_program bpf;
    bpf_u_int32 net_mask;
    bpf_u_int32 src_ip;

    if (!*device)
    {
        if (pcap_findalldevs(&devices, errbuf)) {
            fprintf(stdin, "pcap_findalldevs(): %s\n", errbuf);
            return NULL;
        }
        strcpy(device, devices[0].name);
    }

    // Get network device source IP address and netmask.
    if (pcap_lookupnet(device, &srcip, &netmask, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
        return NULL;
    }

    // Open the device for live capture.
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        return NULL;
    }

    // Convert the packet filter epxression into a packet filter binary.
    if (pcap_compile(handle, &bpf, filter, 0, netmask) == PCAP_ERROR) {
        fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handle));
        return NULL;
    }

    // Bind the packet filter to the libpcap handle.
    if (pcap_setfilter(handle, &bpf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(handle));
        return NULL;
    }

    return handle;    
}
*/


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
