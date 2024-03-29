/**********************************************************/
/*                                                        */
/* File: error.h                                          */
/* Created: 2022-02-19                                    */
/* Last change: 2022-02-28                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project 2 for course IPK                      */
/* Description: Header file for errors                    */
/*                                                        */
/**********************************************************/

#ifndef IPK_SNIFFER_ERROR_H
#define IPK_SNIFFER_ERROR_H

#include <stdio.h>
#include <stdint.h>

enum error
{
    NO_ERROR,
    OPT_ERROR,
    TIME_ERROR,
    PCAP_LOOP_ERR,
    PCAP_LOOKUPNET_ERR,
    PCAP_OPEN_LIVE_ERR,
    PCAP_COMPILE_ERR,
    PCAP_SETFILTER_ERR,
    UNKNOWN_ERROR
};

void print_error(uint8_t error);

#endif // IPK_SNIFFER_ERROR_H
