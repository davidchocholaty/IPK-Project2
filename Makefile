#**********************************************************
#
# File: Makefile
# Created: 2022-02-12
# Last change: 2022-02-28
# Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>
# Project: Project 2 for course IPK
# Description: Makefile for packet sniffer
#
#**********************************************************

CC = gcc
CFLAGS = -std=gnu99 -Wall -Wextra -Werror -pedantic -g
LDFLAGS = -lpcap
EXECUTABLE = ipk-sniffer
ERR = error
OPT = option
PACKET_PRINT = packet-print
OBJS = $(EXECUTABLE).o $(ERR).o $(OPT).o $(PACKET_PRINT).o
LOGIN = xchoch09
TAR_FILE = $(LOGIN).tar
TAR_OPTIONS =  --exclude-vcs -cvf

.PHONY: all pack run clean

all: $(EXECUTABLE)

pack: $(TAR_FILE)

run: $(EXECUTABLE)
	./$(EXECUTABLE) $(ARGS)

$(EXECUTABLE): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(EXECUTABLE) *.o $(TAR_FILE)

$(TAR_FILE): *.c *.h Makefile README.md manual.pdf
	tar $(TAR_OPTIONS) $@ $^
