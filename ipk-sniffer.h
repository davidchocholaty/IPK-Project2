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

#include <pcap.h>
#include <signal.h>

#include "error.h"
#include "option.h"

#define DLT_NULL_LEN       4
#define DLT_EN10MB_LEN    14
#define DLT_LINUX_SLL_LEN 16
#define DLT_SLIP_PPP_LEN  24

#endif // IPK_SNIFFER_H
