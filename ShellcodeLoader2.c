#include "windows.h"
#include <stdio.h>

int main()
{
    FILE* f = fopen("test.bin", "rb");
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    void* exec = VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    fread(exec, 1, size, f);
    fclose(f);
    
    ((void(*)())exec)();
    return 0;
}
