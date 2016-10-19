#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Get a recorded PCAP file, assume that payload is 16 bits RGB565, save the payload to the PNG image file
# Data can come from OV7691
'''
The script parses the Windows BSOD dumpfiles. It handles only files which start with 
'PAGEDU64' or 'PAGEDUMP'
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
        hex_str = format(ord(b), 'x')
        if (len(hex_str) < 2):
            hex_str = '0'+hex_str
        s = hex_str + s
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

DUMP_0x2000_STRUCT = (
    DataField("Uknwn", 4),  # 2000
    DataField("DumbBlob", 4), # DumbBlob (hardware?)  
    DataField("StackRva", 4),
    
    DataField("Uknwn", 4), # 2010
    DataField("Uknwn", 4),
    DataField("Uknwn", 4),
    DataField("Uknwn", 4),

    DataField("Uknwn", 4), # 2020
    DataField("Uknwn", 4),
    DataField("Uknwn", 4),
    DataField("Uknwn", 4),

    DataField("Uknwn", 4), # 2030
    DataField("Uknwn", 4),
    DataField("StringsRva", 4),
    DataField("Uknwn", 4),
);

DUMP_STACK64_STRUCT = (
    DataField("Uknwn", 8),
    DataField("Uknwn", 8),
    DataField("Uknwn", 8),
    DataField("Uknwn", 8),
    DataField("Uknwn", 8),
    DataField("Uknwn", 8),
    DataField("Uknwn", 8),
    DataField("Uknwn", 8),
    DataField("Address", 8),
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
    DataField("Unknown", 4),
    DataField("BugCheckParameter", 4*8),
    DataField("Skip", 0x20),
    DataField("KdDebuggerDataBlock", 8),
    DataField("PhysicalMemoryBlockBuffer", 0x2C0, PHYSICAL_MEMORY_DESCRIPTOR64_STRUCT),
    DataField("ContextRecord", 3000),
    DataField("Exception", 0x98, EXCEPTION_RECORD64_STRUCT),
    DataField("DumpType", 8),
    DataField("RequiredDumpSpace", 8),
    DataField("SystemTime", 8),
    DataField("Comment", 128),
    DataField("SystemUpTime", 8),
    DataField("MiniDumpFields", 4),
    DataField("SecondaryDataState", 4),
    DataField("ProductType", 4),
    DataField("WriterStatus", 4),
    DataField("Unused1", 1),
    DataField("KdSecondaryVersion", 1),
    DataField("Unused2", 2),
    DataField("Reserved", 0xfb4),
    # Offset  0x2000  
    DataField("DUMP_0x2000_STRUCT", 4, DUMP_0x2000_STRUCT),
);

VS_FIXEDFILEINFO_STRUCT = (
    DataField("dwSignature", 4),
    DataField("dwStrucVersion", 4),
    DataField("dwFileVersionMS", 4),
    DataField("dwFileVersionLS", 4),
    DataField("dwProductVersionMS", 4),
    DataField("dwProductVersionLS", 4),
    DataField("dwFileFlagsMask", 4),
    DataField("dwFileFlags", 4),
    DataField("dwFileOS", 4),
    DataField("dwFileType", 4),
    DataField("dwFileSubtype", 4),
    DataField("dwFileDateMS", 4),
    DataField("dwFileDateLS", 4)
);

MINIDUMP_LOCATION_DESCRIPTOR = (
    DataField("DataSize", 4),
    DataField("Rva", 4)
);

MINIDUMP_MODULE64_STRUCT = (
    DataField("BaseOfImage", 8),
    DataField("SizeOfImage", 4),
    DataField("CheckSum", 4),
    DataField("TimeDateStamp", 4),
    DataField("ModuleNameRva", 4),
    DataField("VersionInfo", 4, VS_FIXEDFILEINFO_STRUCT),
    DataField("CvRecord", 4, MINIDUMP_LOCATION_DESCRIPTOR),
    DataField("MiscRecord", 4, MINIDUMP_LOCATION_DESCRIPTOR),
    DataField("Reserved0", 8),
    DataField("Reserved1", 8),
);

MINIDUMP_MODULE_LIST_STRUCT = (
    DataField("NumberOfModules", 4),
    DataField("Modules", 4, MINIDUMP_MODULE64_STRUCT)
);

DUMP_0x2000_STRINGS_STRUCT = (
    DataField("Length", 4),
    DataField("String", 4),
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
            logger.debug("{3}:{0} = {1} ({2})".format(data_field.name, value, value_ascii, hex(file_offset)))
        else:
            logger.debug("{2}:{0} = {1}".format(data_field.name, value, hex(file_offset)))
    else:
        logger.debug("Skip {0} bytes".format(data_field.size))
        
        
    return (value, contains_ascii, value_ascii)

def parse_dump_header_generic_struct(arguments, file_dump, struct):
    for data_field in struct:
        if (not data_field.is_struct):
            parse_field(file_dump, data_field)
        else:
            parse_dump_header_generic_struct(arguments, file_dump, struct)
        
    

def parse_dump_header_physical_memory_block_buffer_64(arguments, file_dump, data_field):
    (value, contains_ascii, value_ascii) = parse_field(file_dump, PHYSICAL_MEMORY_DESCRIPTOR64_STRUCT[0])
    if (value == '4547415045474150'):
        bytes_to_skip = data_field.size
        logger.warn("Skip physical memory descriptors {0} bytes".format(bytes_to_skip))
        read_field(file_dump, bytes_to_skip-PHYSICAL_MEMORY_DESCRIPTOR64_STRUCT[0].size)
        return False
    number_of_pages = parse_field(file_dump, PHYSICAL_MEMORY_DESCRIPTOR64_STRUCT[1])
    return False

def parse_dump_header_exception_64(arguments, file_dump):
    (exception_code, exception_flags, exception_address) = (None, None, None)
    for data_field in EXCEPTION_RECORD64_STRUCT:
        (value, contains_ascii, value_ascii) = parse_field(file_dump, data_field)
        if (data_field.name == "ExceptionCode"):
            exception_code = int(value, 16)
        if (data_field.name == "ExceptionFlags"):
            exception_flags = int(value, 16)
        if (data_field.name == "ExceptionAddress"):
            exception_address = int(value, 16)
            
    return (exception_code, exception_flags, exception_address)
        

def parse_dump_header_physical_blocks_32(arguments, file_dump):
    number_of_runs = parse_field(file_dump, PHYSICAL_MEMORY_DESCRIPTOR32_STRUCT[0])
    number_of_pages = parse_field(file_dump, PHYSICAL_MEMORY_DESCRIPTOR32_STRUCT[1])

def parse_dump_header_0x2000(arguments, file_dump):
    strings_offset, stack_offset = None, None
    for data_field in DUMP_0x2000_STRUCT:
        (value, contains_ascii, value_ascii) = parse_field(file_dump, data_field)
        if (data_field.name == "StringsRva"):
            strings_offset = int(value, 16)
            logger.debug("Loaded modules names at offset {0}".format(hex(strings_offset)))
        if (data_field.name == "StackRva"):
            stack_offset = int(value, 16)
            logger.debug("Stack frames at offset {0}".format(hex(stack_offset)))
    return (strings_offset, stack_offset)

def parse_stack_frames64(arguments, file_dump, stack_offset):
    file_dump_cursor = file_dump.tell()
    
    file_dump.seek(stack_offset)
    
    stack_addresses = []
    for data_field in DUMP_STACK64_STRUCT:
        if (data_field.name == "Address"):
            while (True):
                (value, contains_ascii, value_ascii) = parse_field(file_dump, data_field)
                stack_address = int(value, 16)
                stack_addresses.append(stack_address)
                if (stack_address == 0):
                    break
        else:
            (value, contains_ascii, value_ascii) = parse_field(file_dump, data_field)

        
        
    file_dump.seek(file_dump_cursor)
    return stack_addresses

def parse_strings(arguments, file_dump, strings_offset):
    file_dump_cursor = file_dump.tell()
    
    file_dump.seek(strings_offset)
    # End of the strings section is 16 bits zero
    while (True):
        file_offset = file_dump.tell()
        cursor_tmp = file_dump.tell()
        data = read_field(file_dump, 4)
        length_hex = data_to_hex(data)
        length = int(length_hex, 16)
        if (length == 0):
            logger.debug("{0}: Length is zero".format(hex(strings_offset)))
            break
        if (length > 256):
            logger.debug("{0}:Length is {1} bytes".format(hex(cursor_tmp), length))
            break
        string = read_field(file_dump, 2*length)
        (contains_ascii, string_ascii) = data_to_ascii(string, 256)
        logger.debug("{0}: length={1},'{2}'".format(hex(file_offset), length, string_ascii))
        
        cursor_tmp = file_dump.tell()
        data = read_field(file_dump, 2) # I expect zero terminaiton here
        zero_hex = data_to_hex(data)
        zero = int(zero_hex, 16)  
        if (zero != 0):
            logger.debug("{0}:Missing zero termination - got {1} instead".format(hex(cursor_tmp), zero_hex))
            break
        
    file_dump.seek(file_dump_cursor)
        
'''
 print pykd.getStack()
[<pykd.pykd.stackFrame object at 0x0000000002CBDB38>, <pykd.pykd.stackFrame object at 0x0000000002D16278>, <pykd.pykd.stackFrame object at 0x000000000
2D162E8>, <pykd.pykd.stackFrame object at 0x0000000002D16358>, <pykd.pykd.stackFrame object at 0x0000000002D163C8>, <pykd.pykd.stackFrame object at 0x
0000000002D16438>, <pykd.pykd.stackFrame object at 0x0000000002D164A8>]
>>> print pykd.getStack()[0]
Frame: IP=fffff800026d4f00  Return=fffff800026d4469  Frame Offset=fffff80000ba4d20  Stack Offset=fffff80000ba4d28
>>> print pykd.getStack()[1]
Frame: IP=fffff800026d4469  Return=7f  Frame Offset=fffff80000ba4d28  Stack Offset=fffff80000ba4d30
>> print pykd.getStack()[2]
Frame: IP=7f  Return=8  Frame Offset=fffff80000ba4d30  Stack Offset=fffff80000ba4d38
>>> print pykd.getStack()[3]
Frame: IP=8  Return=80050031  Frame Offset=fffff80000ba4d38  Stack Offset=fffff80000ba4d40
>>> print pykd.getStack()[4]
Frame: IP=80050031  Return=406f8  Frame Offset=fffff80000ba4d40  Stack Offset=fffff80000ba4d48
>>> print pykd.getStack()[5]
Frame: IP=406f8  Return=fffff88001127c0b  Frame Offset=fffff80000ba4d48  Stack Offset=fffff80000ba4d50
>>> print pykd.getStack()[6]
Frame: IP=fffff88001127c0b  Return=0  Frame Offset=fffff80000ba4d50  Stack Offset=fffff80000ba4d58
>>> print pykd.getStack()[7]
Traceback (most recent call last):

   61 00003c0: 304e ba00 00f8 ffff return[1]=7f00 0000 0000 0000  0N..............
   62 00003d0: ip[3]0800 0000 0000 0000 return[x]306a f009 80fa ffff  ........0j......
   63 00003e0: stackoff[0] 284d ba00 00f8 ffff f04e ba00 00f8 ffff  (M.......N......
   64 00003f0: f0d5 eb09 80fa ffff ip[x]306a f009 80fa ffff  ........0j......
   65 0000400: ip[4]=3100 0580 0000 0000 return[4]=f806 0400 0000 0000  1...............
   66 0000410: return[5]=0b7c 1201 80f8 ffff 80e2 2c05 80f8 ffff  .|........,.....
   67 0000420: e0e0 2c05 80f8 ffff return[x]=006a f009 80fa ffff  ..,......j......
   68 0000430: 0185 ef0b a0f8 ffff 58e1 2c05 80f8 ffff  ........X.,.....
   69 0000440: ip[0]=004f 6d02 00f8 ffff 8a00 f800 0000 0000  .Om.............
   70 0000450: 8074 9b0b a0f8 ffff return[6]=0000 0000 0000 0000  .t..............
   
 0014770: 0000 0000 0000 0000 0000 0000 0000 0000  ................
 0014780: 304e ba00 00f8 ffff 7f00 0000 0000 0000  0N..............
 0014790: 0800 0000 0000 0000 306a f009 80fa ffff  ........0j......
 00147a0: 284d ba00 00f8 ffff f04e ba00 00f8 ffff  (M.......N......
 00147b0: f0d5 eb09 80fa ffff 306a f009 80fa ffff  ........0j......
 00147c0: 3100 0580 0000 0000 f806 0400 0000 0000  1...............
 00147d0: 0b7c 1201 80f8 ffff 80e2 2c05 80f8 ffff  .|........,.....
 00147e0: e0e0 2c05 80f8 ffff 006a f009 80fa ffff  ..,......j......
 00147f0: 0185 ef0b a0f8 ffff 58e1 2c05 80f8 ffff  ........X.,.....
 0014800: 004f 6d02 00f8 ffff 0000 0000 0000 0000  .Om.............
 0014810: 0000 0000 0000 0000 0000 0000 0000 0000  ................


    1 0000000: 5041 4745 4455 3634 0f00 0000 b01d 0000  PAGEDU64........
    2 0000010: 00d0 6d1e 0000 0000 20b2 9002 00f8 ffff  ..m..... .......
    3 0000020: 500e 8a02 00f8 ffff 302b 8802 00f8 ffff  P.......0+......
    4 0000030: 6486 0000 0100 0000 7f00 0000 5041 4745  d...........PAGE
    5 0000040: 0800 0000 0000 0000 3100 0580 0000 0000  ........1.......
    6 0000050: f806 0400 0000 0000 0b7c 1201 80f8 ffff  .........|......

line 2799 0x14780
0000000000000000000000000000000000000000
304eba0000f8ffff
7f00000000000000 = ip[2]
0800000000000000 = ip[3]
306af00980faffff = 
28 4d ba 0000f8ffff = stack[0]
f04eba0000f8ffff
f0d5eb0980faffff = return[ ]
306af00980faffff = return[ ]
3100058000000000 = return[3]
f806040000000000 = return[4]
0b7c120180f8ffff = return[5]
80e22c0580f8ffff
e0e02c0580f8ffff
006af00980faffff
0185ef0ba0f8ffff
58e12c0580f8ffff
004f6d0200f8ffff 
000000000000000000000000000000000000000000000000
'''
def parse_dump_header_64(arguments, file_dump):
    logger.info("64bits dump")
    skip = True
    physical_memory_presents = False
        
    for data_field in HEADER64_STRUCT:
        if (data_field.name == "MajorVersion"):
            skip = False
        if skip:
            continue
        if (not data_field.is_struct):
            (value, contains_ascii, value_ascii) = parse_field(file_dump, data_field)
        else:
            if (data_field.name == "PhysicalMemoryBlockBuffer"):
                physical_memory_presents = parse_dump_header_physical_memory_block_buffer_64(arguments, file_dump, data_field)
            elif (data_field.name == "Exception"):
                (exception_code, exception_flags, exception_address) = parse_dump_header_exception_64(arguments, file_dump)
                logger.info("Exception: code={0}, address={1}, flags={2}".format(hex(exception_code), hex(exception_address), hex(exception_flags)))
            elif (data_field.name == "DUMP_0x2000_STRUCT"):
                strings_offset, stack_offset = parse_dump_header_0x2000(arguments, file_dump)
                parse_strings(arguments, file_dump, strings_offset)
                stack_addresses = parse_stack_frames64(arguments, file_dump, stack_offset)
                logger.info("Stack: {0}".format(stack_addresses))
            else:
                parse_dump_header_generic_struct(arguments, file_dump, data_field.data_struct)
    return physical_memory_presents;
                
    
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
                    physical_memory_presents = parse_dump_header_64(arguments, file_dump)
                else:
                    physical_memory_presents = parse_dump_header_32(arguments, file_dump)
            
                break
            
    if (not physical_memory_presents):
        logger.info("No physical memory presents in the dump file")

            
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
    logger.setLevel(logging.DEBUG)

    is_parse = arguments["parse"]

    if is_parse:
        parse_dump(arguments)
