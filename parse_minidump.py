#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Get a recorded PCAP file, assume that payload is 16 bits RGB565, save the payload to the PNG image file
# Data can come from OV7691
'''
The script parses the Windows BSOD dumpfiles. It handles only files which start with 
'PAGEDU64' or 'PAGEDUMP'
Example of output
INFO:parser:Parse file '../winvm/minidump.dmp'
INFO:parser:64bits dump
INFO:parser:Exception: code=0x80000003, address=0xfffff800026d4f00L, flags=0x1
.......................
INFO:parser:Stack: 0xfffff88001127c0bL, \.S.y.s.t.e.m.R.o.o.t.\.s.y.s.t.e.m.3.2.\.d.r.i.v.e.r.s.\.f.l.t.m.g.r...s.y.s.......
.......................
INFO:parser:Stack: 0xfffff800026d4f00L, \.S.y.s.t.e.m.R.o.o.t.\.s.y.s.t.e.m.3.2.\.n.t.o.s.k.r.n.l...e.x.e...
.......................

Usage:
    parse_minidump.py parse --filein=FILENAME [--debuglevel=LEVEL] 


Options:
    --filein=FILENAME file to convert
    --debuglevel=Debug print level [default: INFO]

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

DUMP_0x1000_STRUCT = (
    DataField("Uknwn", 4),  # 1000
    DataField("DumbBlob", 4), # DumbBlob (hardware?)  
    DataField("Uknwn", 4),
    
    DataField("StackRva", 4), 
    DataField("Uknwn", 4),
    DataField("Uknwn", 4),
    DataField("Uknwn", 4),

    DataField("Uknwn", 4), 
    DataField("Uknwn", 4),
    DataField("Uknwn", 4),
    DataField("Uknwn", 4),

    DataField("Uknwn", 4), 
    DataField("LoadedModules", 4),
    DataField("Uknwn", 4),
    DataField("StringsRva", 4),
);


     
HEADER32_STRUCT = (
    DataField("Signature", 4),
    DataField("ValidDump", 4),
    DataField("MajorVersion", 4),
    DataField("MinorVersion", 4),
    DataField("DirectoryTableBase", 4),  # 00185000
    DataField("PfnDataBase", 4),         # 82977838
    DataField("PsLoadedModuleList", 4),  # 82956e30
    DataField("PsActiveProcessHead", 4), # 8294f4f0
    DataField("PsActiveProcessHead", 4), # 828a014c 
    DataField("MachineImageType", 4),    # 00000100
    DataField("NumberProcessors", 4),    # 1000007e
    DataField("BugCheckCode", 4),        # c0000005 
    DataField("Skip", 4),
    DataField("Skip", 4),
    DataField("Skip", 0x320-0x38),
    DataField("BugCheckParameter", 4*4),
    DataField("Skip", 0x20),
    DataField("KdDebuggerDataBlock", 4),
    DataField("PhysicalMemoryBlockBuffer", 0x2C0, PHYSICAL_MEMORY_DESCRIPTOR32_STRUCT),
    DataField("ContextRecord", 3000-0x68),
    DataField("Exception", 0x98, EXCEPTION_RECORD32_STRUCT),
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
    # Offset  0x1000  
    DataField("DUMP_0x1000_STRUCT", 4, DUMP_0x1000_STRUCT),
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
    DataField("Uknwn", 4),
    
    DataField("StackRva", 4), 
    DataField("Uknwn", 4),
    DataField("Uknwn", 4),
    DataField("Uknwn", 4),

    DataField("Uknwn", 4), 
    DataField("Uknwn", 4),
    DataField("Uknwn", 4),
    DataField("Uknwn", 4),

    DataField("Uknwn", 4), 
    DataField("LoadedModules", 4),
    DataField("Uknwn", 4),
    DataField("StringsRva", 4),
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

'''
 2231 0008b60: 80d4 0000 0000 0000 0000 0000 0000 0000  ................
 2232 0008b70: 0000 0000 0000 0000 0000 0000 0000 0000  ................
 2233 0008b80: 0000 0000 0000 0000 0000 0000 0000 0000  ................
 2234 0008b90: 0000 0000 0000 0000 0030 6602 00f8 ffff  .........0f.....
 2235 0008ba0: 0000 0000 0000 0000 00d0 5d00 0000 0000  ..........].....
 2236 0008bb0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
 2237 0008bc0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
 2238 0008bd0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
 2239 0008be0: 87b4 5400 0000 0000 00c6 5b4a 0000 0000  ..T.......[J....
'''
LOADED_MODULE64_STRUCT = (
    DataField("Path", 4),
    DataField("Skip", 4+8+16+16+8),
    DataField("BaseAddress", 8),
    DataField("Uknwn", 8),
    DataField("Size", 8),
    DataField("Skip", 3*16),
    DataField("Uknwn", 16),
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
        logger.debug("Skip physical memory descriptors {0} bytes".format(bytes_to_skip))
        read_field(file_dump, bytes_to_skip-PHYSICAL_MEMORY_DESCRIPTOR64_STRUCT[0].size)
        return False
    number_of_pages = parse_field(file_dump, PHYSICAL_MEMORY_DESCRIPTOR64_STRUCT[1])
    return False

class Exception:
    def __init__(self, code, flags, address):
        self.code, self.flags, self.address = code, flags, address
        
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
            
    return Exception(exception_code, exception_flags, exception_address)
        

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
        if (data_field.name == "LoadedModules"):
            modules_offset = int(value, 16)
            logger.debug("Loaded modules at offset {0}".format(hex(modules_offset)))
    return (strings_offset, stack_offset, modules_offset)

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

def parse_strings(arguments, file_dump, string_offset_base):
    file_dump_cursor = file_dump.tell()
    
    file_dump.seek(string_offset_base)
    # End of the strings section is 16 bits zero
    strings_offset = string_offset_base
    strings = {}
    while (True):
        file_offset = file_dump.tell()
        cursor_tmp = file_dump.tell()
        strings_offset = cursor_tmp # - string_offset_base
        data = read_field(file_dump, 4)
        length_hex = data_to_hex(data)
        length = int(length_hex, 16)
        if (length == 0):
            logger.debug("{0}: Length is zero".format(hex(cursor_tmp)))
            break
        if (length > 256):
            logger.debug("{0}:Length is {1} bytes".format(hex(cursor_tmp), length))
            break
        # The whole string - length, chars, zero termination - should be 64 bits aligned
        # padded by zeros
        bytes_to_read = 2*length+2+4  
        bytes_to_read = (bytes_to_read + 7) & (~7)
        string = read_field(file_dump, bytes_to_read-4)  # I read 4 bytes of length already  
        (contains_ascii, string_ascii) = data_to_ascii(string, 256)
        strings[strings_offset] = string_ascii
        #logger.debug("{0}: length={1},bytes={2},'{3}'".format(hex(file_offset), length, bytes_to_read, string_ascii))
        
    file_dump.seek(file_dump_cursor)
    
    return strings
        
def parse_module(arguments, file_dump):
    module_name_offset, module_address, module_size = None, None, None
    for data_field in LOADED_MODULE64_STRUCT:
        (value, contains_ascii, value_ascii) = parse_field(file_dump, data_field)
        if (data_field.name == "Path"):
            module_name_offset = int(value, 16)
        if (data_field.name == "BaseAddress"):
            module_address = int(value, 16)
        if (data_field.name == "Size"):
            module_size = int(value, 16)
            
    return (module_name_offset, module_address, module_size)
    
            
class LoadedModule:
    def __init__(self, name_offset, address, size):
        self.name_offset, self.address, self.size = name_offset, address, size
        pass
                
def parse_modules(arguments, file_dump, modules_offset_base):
    
    file_dump_cursor = file_dump.tell()
    
    file_dump.seek(modules_offset_base)
    modules = []
    while (True):
        (name_offset, address, size) = parse_module(arguments, file_dump)
        if (name_offset >= 0xFFFF):
            break
        if (name_offset <= modules_offset_base):
            break
        modules.append(LoadedModule(name_offset, address, size))
        
    file_dump.seek(file_dump_cursor)
 
    return modules
        


def find_module_by_address(loaded_modules, address):
    for loaded_module in loaded_modules:
        start_address = loaded_module.address
        end_address = start_address + loaded_module.size
        if (address >= start_address) and (address <= end_address):
            return (True, loaded_module)
    
    return (False, None)

class StackFrame:
    def __init__(self, address, loaded_module=None):
        self.address, self.loaded_module = address, loaded_module
        
def parse_dump_header_64(arguments, file_dump):
    logger.debug("64bits dump")
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
                exception = parse_dump_header_exception_64(arguments, file_dump)
                logger.debug("Exception: code={0}, address={1}, flags={2}".format(hex(exception.code), hex(exception.address), hex(exception.flags)))
            elif (data_field.name == "DUMP_0x2000_STRUCT"):
                strings_offset, stack_offset, modules_offset = parse_dump_header_0x2000(arguments, file_dump)
                loaded_modules_names = parse_strings(arguments, file_dump, strings_offset)
                for loaded_modules_offset in loaded_modules_names:
                    loaded_modules_name = loaded_modules_names[loaded_modules_offset]
                    logger.debug("Module: {0}:{1}".format(hex(loaded_modules_offset), loaded_modules_name))
                stack_addresses = parse_stack_frames64(arguments, file_dump, stack_offset)
                loaded_modules = parse_modules(arguments, file_dump, modules_offset)
                
                for loaded_module in loaded_modules:
                    logger.debug("Loaded module: name_rva={0}, address={1}, size={2}".format(hex(loaded_module.name_offset), hex(loaded_module.address), hex(loaded_module.size)))
                    loaded_module.name = loaded_modules_names[loaded_module.name_offset]
                    logger.debug("{0}:address={1}, size={2}".format(loaded_module.name, hex(loaded_module.address), loaded_module.size))
            else:
                parse_dump_header_generic_struct(arguments, file_dump, data_field.data_struct)
    stack_frames = []
    for stack_address in stack_addresses:
        (module_found, loaded_module) = find_module_by_address(loaded_modules, stack_address)
        stack_frames.append(StackFrame(stack_address, loaded_module))
    return (physical_memory_presents, stack_frames, exception);
                
    
def parse_dump_header_32(arguments, file_dump):
    logger.debug("32bits dump")
    skip = True
    physical_memory_presents = False
        
    for data_field in HEADER32_STRUCT:
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
                exception = parse_dump_header_exception_64(arguments, file_dump)
                logger.debug("Exception: code={0}, address={1}, flags={2}".format(hex(exception.code), hex(exception.address), hex(exception.flags)))
            elif (data_field.name == "DUMP_0x2000_STRUCT"):
                strings_offset, stack_offset, modules_offset = parse_dump_header_0x2000(arguments, file_dump)
                loaded_modules_names = parse_strings(arguments, file_dump, strings_offset)
                for loaded_modules_offset in loaded_modules_names:
                    loaded_modules_name = loaded_modules_names[loaded_modules_offset]
                    logger.debug("Module: {0}:{1}".format(hex(loaded_modules_offset), loaded_modules_name))
                stack_addresses = parse_stack_frames64(arguments, file_dump, stack_offset)
                loaded_modules = parse_modules(arguments, file_dump, modules_offset)
                
                for loaded_module in loaded_modules:
                    logger.debug("Loaded module: name_rva={0}, address={1}, size={2}".format(hex(loaded_module.name_offset), hex(loaded_module.address), hex(loaded_module.size)))
                    loaded_module.name = loaded_modules_names[loaded_module.name_offset]
                    logger.debug("{0}:address={1}, size={2}".format(loaded_module.name, hex(loaded_module.address), loaded_module.size))
            else:
                parse_dump_header_generic_struct(arguments, file_dump, data_field.data_struct)
    stack_frames = []
    for stack_address in stack_addresses:
        (module_found, loaded_module) = find_module_by_address(loaded_modules, stack_address)
        stack_frames.append(StackFrame(stack_address, loaded_module))
    return (physical_memory_presents, stack_frames, exception);


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
                    (physical_memory_presents, stack_frames, exception) = parse_dump_header_64(arguments, file_dump)
                else:
                    (physical_memory_presents, stack_frames, exception) = parse_dump_header_32(arguments, file_dump)
            
                break
            
            
    return (dump_type_64, physical_memory_presents, stack_frames, exception)
                 
                    
                

def parse_dump(arguments):
    filename_in = arguments["--filein"]
    logger.debug("Parse file '{0}'".format(filename_in))
    while True:
        (result, file_dump) = open_file(filename_in, 'rb')
        if not result:
            logger.error("Failed to open file '{0}' for reading".format(filename_in))
            break
        
        (dump_type_64, physical_memory_presents, stack_frames, exception) = parse_dump_header(arguments, file_dump)

        file_dump.close()
        return (dump_type_64, physical_memory_presents, stack_frames, exception)
    
    return (None, None, None)


if __name__ == '__main__':
    arguments = docopt(__doc__, version="parser")

    logging.basicConfig()
    logger = logging.getLogger('parser')
    debug_level = arguments["--debuglevel"]
    if (debug_level == "INFO") or (debug_level == None):
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.DEBUG)
    is_parse = arguments["parse"]

    if is_parse:
        # The goal is to print the stack frames - address and, if possible, module name 
        (dump_type_64, physical_memory_presents, stack_frames, exception) = parse_dump(arguments)
        
        if (dump_type_64 is not None):
            for stack_frame in stack_frames: 
                if (stack_frame.loaded_module != None):
                    logger.info("Stack: {0}, {1}".format(hex(stack_frame.address), stack_frame.loaded_module.name))
                else:
                    logger.info("Stack: {0}".format(hex(stack_frame.address)))
    
            
            if (not physical_memory_presents):
                logger.info("No physical memory presents in the dump file")

