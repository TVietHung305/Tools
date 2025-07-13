import idaapi
import ida_funcs

def Get_all_Call_Func():
    info = idaapi.get_inf_structure()
    start_ea = info.minEA
    end_ea = info.maxEA 
    call_loc = idaapi.find_binary(start_ea, end_ea, "e8", 16, idaapi.SEARCH_DOWN)
    call_locs = []
    while call_loc != idaapi.BADADDR:
        call_locs.append(call_loc)
        call_loc = idaapi.find_binary(call_loc+1, end_ea, "e8", 16, idaapi.SEARCH_DOWN)
    return call_locs

def AddOffset(addr, offset):
    addr += offset
    addr &= 0xffffffff
    return addr
    
def Get_Destination_Address(call_addr):
    esp = call_addr + 5
    return AddOffset(esp, idaapi.get_dword(call_addr + 1))

def Find_target_call():
    call_locs = Get_all_Call_Func()
    calls = {}
    
    for call_loc in call_locs:
        dest = Get_Destination_Address(call_loc)
        calls[dest] = calls.get(dest, 0) + 1
        
    target_ = max(calls, key=calls.get)
    print(f"Target Function: {hex(target_)}")
    count = calls[target_]
    print(count)
    return target_
    
def patch_jump_ins(target_func):
    call_locs = Get_all_Call_Func()
    patched = 0
    
    for call_addr in call_locs:
        dest = Get_Destination_Address(call_addr)
        
        if dest == target_func:
            #Get real target from data after call
            offset_ = idaapi.get_dword(call_addr+5)
            address_to_jump = AddOffset(call_addr + 5, offset_)
            
            #Create jmp instruction 
            jmp_offset = (address_to_jump - (call_addr + 5)) & 0xffffffff
            jmp_bytes = b"\xE9" + jmp_offset.to_bytes(4, "little")
            
            #Patch
            idaapi.patch_bytes(call_addr, jmp_bytes)
            idaapi.auto_make_code(call_addr)
            print("Patched!!")
target_func = Find_target_call()
patch_jump_ins(target_func)
