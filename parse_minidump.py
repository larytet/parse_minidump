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

def data_to_hex(data, max_length=32):
    s = ""
    for b in data:
        s = format(ord(b), 'x') + s
        max_length = max_length - 1
        if (max_length == 0):
            break
        
    return s

def data_to_ascii(data, max_length=32):
    s = ""
    contains_ascii = False
    for b in data:
        b_ascii = ord(b)
        if (b_ascii >= 0x20) and (b_ascii <= 0x7e):
            s =  s + b
            contains_ascii = True
        else:
            s = s + "."
        max_length = max_length - 1
        if (max_length == 0):
            break
    return (contains_ascii, s)
        
def get_bits(value, start, bits):
    mask = get_mask(bits)
    value = value >> start
    value = value & mask
    return value

def get_int(data):
    if (len(data) == 4):
        return struct.unpack("<I", data)[0]
    if (len(data) == 8):
        return struct.unpack("<Q", data)[0]
    else:
        logger.error("Failed to convert data {0} bytes".format(len(data)))
        return -1;

class DataField:
    def __init__(self, name, size, data_struct = None):
        self.name = name
        self.size = size
        self.data_struct = data_struct
        self.is_struct = (data_struct != None)

PHYSICAL_MEMORY_RUN32_STRUCT = (
    DataField("BasePage", 4),
    DataField("PageCount", 4),
);


PHYSICAL_MEMORY_DESCRIPTOR32_STRUCT = (
    DataField("NumberOfRuns", 4),
    DataField("NumberOfPages", 4),
    DataField("Run", 256, PHYSICAL_MEMORY_RUN32_STRUCT)
);

     
HEADER32_STRUCT = (
    DataField("Signature", 4),
    DataField("ValidDump", 4),
    DataField("MajorVersion", 4),
    DataField("MinorVersion", 4),
    DataField("DirectoryTableBase", 4),
    DataField("PfnDataBase", 4), 
    DataField("PsLoadedModuleList", 4),
    DataField("PsActiveProcessHead", 4),
    DataField("MachineImageType", 4),
    DataField("NumberProcessors", 4),
    DataField("BugCheckCode", 4),
    DataField("BugCheckParameter", 16),
    DataField("VersionUser", 32),
    DataField("PaeEnabled", 1),
    DataField("KdSecondaryVersion", 1),
    DataField("Spare", 32),
    DataField("KdDebuggerDataBlock", 32),
    DataField("PhysicalMemoryBlock", 256, PHYSICAL_MEMORY_DESCRIPTOR32_STRUCT)
    # size is 0x1000 bytes
);

PHYSICAL_MEMORY_RUN64_STRUCT = (
    DataField("BasePage", 8),
    DataField("PageCount", 8),
);

PHYSICAL_MEMORY_DESCRIPTOR64_STRUCT = (
    DataField("NumberOfRuns", 8),
    DataField("NumberOfPages", 8),
    DataField("Run", 256, PHYSICAL_MEMORY_RUN64_STRUCT)
);

MINIDUMP_HEADER_STRUCT = (
    DataField("Signature", 4),
    DataField("ValidDump", 4),
    DataField("NumberOfStreams", 4),                  # The number of streams in the minidump directory.
    DataField("StreamDirectoryRva", 4),   # The directory is an array of MINIDUMP_DIRECTORY structures. 
    DataField("CheckSum", 4),
    DataField("TimeDateStamp", 4), 
    DataField("Flags", 8)               # MINIDUMP_TYPE
);


# from file wdm.h
EXCEPTION_MAXIMUM_PARAMETERS = 15 # maximum number of exception parameters

EXCEPTION_RECORD32_STRUCT = (
    DataField("ExceptionCode", 4),
    DataField("ExceptionFlags", 4),
    DataField("ExceptionRecord", 4),
    DataField("ExceptionAddress", 4),
    DataField("NumberParameters", 4),
    DataField("ExceptionInformation", 4*EXCEPTION_MAXIMUM_PARAMETERS)
);

EXCEPTION_RECORD64_STRUCT = (
    DataField("ExceptionCode", 4),
    DataField("ExceptionFlags", 4),
    DataField("ExceptionRecord", 8),
    DataField("ExceptionAddress", 8),
    DataField("NumberParameters", 4),
    DataField("__unusedAlignment", 4),
    DataField("ExceptionInformation", 8*EXCEPTION_MAXIMUM_PARAMETERS)
);
                                    
HEADER64_STRUCT = (
    DataField("Signature", 4),
    DataField("ValidDump", 4),
    DataField("MajorVersion", 4),
    DataField("MinorVersion", 4),
    DataField("DirectoryTableBase", 8),
    DataField("PfnDataBase", 8), 
    DataField("PsLoadedModuleList", 8),
    DataField("PsActiveProcessHead", 8),
    DataField("MachineImageType", 4),
    DataField("NumberProcessors", 4),
    DataField("BugCheckCode", 4),
    DataField("Unknown", 8),
    DataField("BugCheckParameter", 4*8),
    DataField("Skip", 0x40),
    DataField("KdDebuggerDataBlock", 8),
    DataField("PhysicalMemoryBlockBuffer", 0x2C0, PHYSICAL_MEMORY_DESCRIPTOR64_STRUCT),
    DataField("ContextRecord", 3000),
    DataField("Exception", 0x98, EXCEPTION_RECORD64_STRUCT),
    DataField("DumpType", 4),
    # size is 0x2000 bytes 
);

def read_field(file, size):
    data = file.read(size)
    return data

def parse_field(file, data_field):
    file_offset = file.tell()
    data = read_field(file, data_field.size)
    value = data_to_hex(data)
    (contains_ascii, value_ascii) = data_to_ascii(data)
    if (data_field.name != "Skip"):
        if (contains_ascii):
            logger.info("{3}:{0} = {1} ({2})".format(data_field.name, value, value_ascii, hex(file_offset)))
        else:
            logger.info("{2}:{0} = {1}".format(data_field.name, value, hex(file_offset)))
    else:
        logger.info("Skip {0} bytes".format(data_field.size))
        
        
    return (value, contains_ascii, value_ascii)

def parse_dump_header_physical_blocks_64(arguments, file_dump):
    number_of_runs = parse_field(file_dump, PHYSICAL_MEMORY_DESCRIPTOR64_STRUCT[0])
    number_of_pages = parse_field(file_dump, PHYSICAL_MEMORY_DESCRIPTOR64_STRUCT[1])

def parse_dump_header_physical_blocks_32(arguments, file_dump):
    number_of_runs = parse_field(file_dump, PHYSICAL_MEMORY_DESCRIPTOR32_STRUCT[0])
    number_of_pages = parse_field(file_dump, PHYSICAL_MEMORY_DESCRIPTOR32_STRUCT[1])


def parse_dump_header_64(arguments, file_dump):
    logger.info("64bits dump")
    skip = True
        
    for data_field in HEADER64_STRUCT:
        if (data_field.name == "MajorVersion"):
            skip = False
        if skip:
            continue
        if (not data_field.is_struct):
            (value, contains_ascii, value_ascii) = parse_field(file_dump, data_field)
        else:
            if (data_field.name == "PhysicalMemoryBlock"):
                parse_dump_header_physical_blocks_64(arguments, file_dump)
    
def parse_dump_header_32(arguments, file_dump):
    logger.info("32bits dump")
    skip = True
    for data_field in HEADER64_STRUCT:
        if (data_field.name == "MajorVersion"):
            skip = False
        if skip:
            continue
        if (not data_field.is_struct):
            (value, contains_ascii, value_ascii) = parse_field(file_dump, data_field)
        else:
            if (data_field.name == "PhysicalMemoryBlock"):
                parse_dump_header_physical_blocks_32(arguments, file_dump)


def parse_dump_header(arguments, file_dump):
    dump_type_64 = None
    for data_field in HEADER32_STRUCT:
        if (not data_field.is_struct):
            (value, contains_ascii, value_ascii) = parse_field(file_dump, data_field)
            if (data_field.name == "Signature"):
                if (value_ascii != "PAGE"):
                    logger.error("Failed to parse header in the file '{0}' - no signature. {1} instead of expected {2}".format(filename_in, value_ascii, "PAGE"))
                    break
            if (data_field.name == "ValidDump"):
                dump_type_64 = (value_ascii == "DU64") 
                if (dump_type_64):
                    parse_dump_header_64(arguments, file_dump)
                else:
                    parse_dump_header_32(arguments, file_dump)
            
                break
            
            
    return dump_type_64
                 
                    
                

def parse_dump(arguments):
    filename_in = arguments["--filein"]
    logger.info("Parse file '{0}'".format(filename_in))
    while True:
        (result, file_dump) = open_file(filename_in, 'rb')
        if not result:
            logger.error("Failed to open file '{0}' for reading".format(filename_in))
            break
        parse_dump_header(arguments, file_dump)
        
        file_dump.close()
        break


if __name__ == '__main__':
    arguments = docopt(__doc__, version="parser")

    logging.basicConfig()
    logger = logging.getLogger('parser')
    logger.setLevel(logging.INFO)

    is_parse = arguments["parse"]

    if is_parse:
        parse_dump(arguments)
