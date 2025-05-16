from idaapi import *
from idautils import *
from idc import *

def extract_value(start_addr, end_addr):
    curr_addr = start_addr
    res = []
    while curr_addr <= end_addr:
        mnem = print_insn_mnem(curr_addr)
        if mnem == "mov":
            op = print_operand(curr_addr, 1)
            op = (op.split('h')[0]).strip()
            op = int(op, 16)
            res.append(op)
        curr_addr = next_head(curr_addr, end_addr)
    for i, val in enumerate(res):
        if i > 0:
            print(', ', end = "")
        print(f"0x{val:02X}", end="")

extract_value(0x0041DAD4, 0x0041DB51)
