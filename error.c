/**********************************************************/
/*                                                        */
/* File: error.c                                          */
/* Created: 2022-02-19                                    */
/* Last change: 2022-02-19                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project 2 for course IPK                      */
/* Description: Errors for packet sniffer                 */
/*                                                        */
/**********************************************************/

#include "error.h"

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
