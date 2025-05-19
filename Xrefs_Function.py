import pefile
import struct
from capstone import *
from capstone.x86_const import *

xrefs = {}
pe_file = pefile.PE(input("Enter your binary file to disassemble: "))

match pe_file.FILE_HEADER.Machine:
    case 0x14c:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    case 0x8664:
        md = Cs(CS_ARCH_X86, CS_MODE_64)

offset = 0
for section in pe_file.sections:
    if (section.Characteristics & 0x20000000 == 0x20000000):    #.text
        for i in md.disasm(section.get_data(), 0, section.SizeOfRawData):
            if i.mnemonic == "call" and i.bytes[0] == 0xe8:
                offset = struct.unpack("<i", i.bytes[1:])[0]
                mapped_addr = i.address + pe_file.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                func_addr = hex(mapped_addr + offset)
                if not func_addr in xrefs:
                    xrefs[func_addr] = list()
                xrefs[func_addr].append(hex(mapped_addr))
print(xrefs)