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

def data_to_hex(data):
    s = ""
    for b in data:
        s = format(ord(b), 'x') + s
        
    return s

def data_to_ascii(data):
    s = ""
    contains_ascii = False
    for b in data:
        b_ascii = ord(b)
        if (b_ascii >= 0x20) and (b_ascii <= 0x7e):
            s =  s + b
            contains_ascii = True
        else:
            s = s + "."
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
        
    


MINIDUMP_TYPE =  { 
  0x00000000 : "MiniDumpNormal                          ",
  0x00000001 : "MiniDumpWithDataSegs                    ",
  0x00000002 : "MiniDumpWithFullMemory                  ",
  0x00000004 : "MiniDumpWithHandleData                  ",
  0x00000008 : "MiniDumpFilterMemory                    ",
  0x00000010 : "MiniDumpScanMemory                      ",
  0x00000020 : "MiniDumpWithUnloadedModules             ",
  0x00000040 : "MiniDumpWithIndirectlyReferencedMemory  ",
  0x00000080 : "MiniDumpFilterModulePaths               ",
  0x00000100 : "MiniDumpWithProcessThreadData           ",
  0x00000200 : "MiniDumpWithPrivateReadWriteMemory      ",
  0x00000400 : "MiniDumpWithoutOptionalData             ",
  0x00000800 : "MiniDumpWithFullMemoryInfo              ",
  0x00001000 : "MiniDumpWithThreadInfo                  ",
  0x00002000 : "MiniDumpWithCodeSegs                    ",
  0x00004000 : "MiniDumpWithoutAuxiliaryState           ",
  0x00008000 : "MiniDumpWithFullAuxiliaryState          ",
  0x00010000 : "MiniDumpWithPrivateWriteCopyMemory      ",
  0x00020000 : "MiniDumpIgnoreInaccessibleMemory        ",
  0x00040000 : "MiniDumpWithTokenInformation            ",
  0x00080000 : "MiniDumpWithModuleHeaders               ",
  0x00100000 : "MiniDumpFilterTriage                    ",
  0x001fffff : "MiniDumpValidTypeFlags                  "
};

'''
https://msdn.microsoft.com/en-us/library/ms680383%28v=vs.85%29.aspx
'''
MINIDUMP_LOCATION_DESCRIPTOR_STRUCT = (
  DataField("DataSize", 4),
  DataField("RVA", 4)  # byte offset of the data stream from the beginning of the minidump file
);

MINIDUMP_DIRECTORY_STRUCT = (
    DataField("StreamType", 4),
    DataField("Location", 1, MINIDUMP_LOCATION_DESCRIPTOR_STRUCT)
);

'''
Based on https://msdn.microsoft.com/en-us/library/ms680378%28v=vs.85%29.aspx
'''
MINIDUMP_HEADER_STRUCT = (
    DataField("Signature", 4),
    DataField("ValidDump", 4),
    DataField("NumberOfStreams", 4),                  # The number of streams in the minidump directory.
    DataField("StreamDirectoryRva", 4),   # The directory is an array of MINIDUMP_DIRECTORY structures. 
    DataField("CheckSum", 4),
    DataField("TimeDateStamp", 4), 
    DataField("Flags", 8)               # MINIDUMP_TYPE
);

def parse_minidump_location_descriptor(arguments, file_dump):
    (data, data_hex, contains_ascii, value_ascii) = parse_field(file_dump, MINIDUMP_LOCATION_DESCRIPTOR_STRUCT[0])
    data_size = get_int(data)
    (data, data_hex, contains_ascii, value_ascii) = parse_field(file_dump, MINIDUMP_LOCATION_DESCRIPTOR_STRUCT[1])
    rva = get_int(data)
    return (data_size, rva)
    
def parse_minidump_directory(arguments, file_dump):
    for data_field in MINIDUMP_DIRECTORY_STRUCT:
        (data, data_hex, contains_ascii, value_ascii) = parse_field(file_dump, data_field)
        stream_type = get_int(data)
        (data_size, data_offset) = parse_minidump_location_descriptor(arguments, file_dump)
        logger.info("Stream {0}, size {1} bytes, offset {2}".format(stream_type, data_size, data_offset));
        
        
    
def parse_minidump_header(arguments, file_dump):
    for data_field in MINIDUMP_HEADER_STRUCT:
        if (not data_field.is_struct):
            (data, data_hex, contains_ascii, value_ascii) = parse_field(file_dump, data_field)
            if (data_field.name == "Signature"):
                if (value_ascii != "PAGE"):
                    logger.error("Failed to parse header in the file '{0}' - no signature. {1} instead of expected {2}".format(filename_in, value_ascii, "PAGE"))
                    break
            if (data_field.name == "ValidDump"):
                dump_type_64 = (value_ascii == "DU64") 
                if (dump_type_64):
                    logger.info("64bits dump")
                else:
                    logger.info("32bits dump")
            
            if data_field.name == "NumberOfStreams":
                number_of_streams = get_int(data)
                logger.info("Number of streams = {0}".format(number_of_streams))
            
            if data_field.name == "StreamDirectoryRva":
                stream_directory_rva = get_int(data)
                logger.info("StreamDirectoryRva = {0}".format(stream_directory_rva))
                #for stream_idx in range(number_of_streams):
                #    parse_minidump_directory(arguments, file_dump)
                break
            
            
    return dump_type_64

def read_field(file, size):
    data = file.read(size)
    return data

def parse_field(file, data_field):
    file_offset = file.tell()
    data = read_field(file, data_field.size)
    data_hex = data_to_hex(data)
    (contains_ascii, value_ascii) = data_to_ascii(data)
    if (data_field.name != "Skip"):
        if (contains_ascii):
            logger.info("{3}:{0} = {1} ({2})".format(data_field.name, data_hex, value_ascii, hex(file_offset)))
        else:
            logger.info("{2}:{0} = {1}".format(data_field.name, data_hex, hex(file_offset)))
    else:
        logger.info("Skip {0} bytes".format(data_field.size))
        
        
    return (data, data_hex, contains_ascii, value_ascii)

def parse_minidump(arguments):
    filename_in = arguments["--filein"]
    logger.info("Parse file '{0}'".format(filename_in))
    while True:
        (result, file_dump) = open_file(filename_in, 'rb')
        if not result:
            logger.error("Failed to open file '{0}' for reading".format(filename_in))
            break
        parse_minidump_header(arguments, file_dump)
        
        file_dump.close()
        break

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
        parse_minidump(arguments)
