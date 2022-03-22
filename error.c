/**********************************************************/
/*                                                        */
/* File: error.c                                          */
/* Created: 2022-02-19                                    */
/* Last change: 2022-03-22                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project 2 for course IPK                      */
/* Description: Errors for packet sniffer                 */
/*                                                        */
/**********************************************************/

#include "error.h"

/*
 * Function for printing error message
 *
 * @param error Error code
 */
void print_error(uint8_t error)
{
    const char *error_msg[] =
    {
        "exit success",
        "wrong option",
        "creating timestamp error",
        "pcap_loop failed",
        "pcap_lookupnet error",
        "pcap_open_live error",
        "pcap_compile error",
        "pcap_setfilter error",
        "unknown error",        
    };
    
    if(error > UNKNOWN_ERROR)
    {
        error = UNKNOWN_ERROR;
    }

    fprintf(stderr, "Error: %s\n", error_msg[error]);    
}
