#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Get a recorded PCAP file, assume that payload is 16 bits RGB565, save the payload to the PNG image file
# Data can come from OV7691
'''
Usage:
    parse_minidump.py parse --filein=FILENAME 


Options:
    --filein=FILENAME file to convert

Example:
    ./parse_minidump.py parse --filein=100916-24960-01.dmp 
'''

import logging
import re
import struct
import time
from datetime import datetime
import subprocess


try:
    from docopt import docopt
except Exception as e:
    print "Try 'pip install -U docopt'"
    print e


def convert_to_int(str_in, base):
    value = None
    try:
        value = int(str_in, base)
        result = True
    except Exception as e:
        logger.error("Bad formed number '{0}'".format(str_in))
        logger.error(e)
        result = False
    return (result, value)

def open_file(filename, flag):
    '''
    Open a file for reading or writing
    Returns handle to the open file and result code False/True
    '''
    try:
        file_handle = open(filename, flag) # read text file
    except Exception as e:
        logger.error('Failed to open file {0}'.format(filename))
        logger.error(e)
        return (False, None)
    else:
        return (True, file_handle)

def get_mask(bits):
    return (1 << bits) - 1


def get_bits(value, start, bits):
    mask = get_mask(bits)
    value = value >> start
    value = value & mask
    return value

def parse_dump(arguments):
    while True:
        filename_in = arguments["--filein"]
        (result, file_dump) = open_file(filename_in, 'rb')
        if not result:
            logger.error("Failed to open file '{0}' for reading".format(filename_in))
            break


if __name__ == '__main__':
    arguments = docopt(__doc__, version='Windows dump file parser')

    logging.basicConfig()
    logger = logging.getLogger('parser')
    logger.setLevel(logging.INFO)

    is_parse = arguments["parse"]

    if is_parse:
        parse_dump(arguments)
