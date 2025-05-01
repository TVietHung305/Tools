/*
Tìm kiếm pattern nhị phân
Mô tả: Viết chương trình tìm kiếm một chuỗi byte cụ thể (pattern) trong file nhị phân và in offset của các lần xuất hiện.
*/
#include<stdio.h>
#include<stdlib.h>
#include<ctype.h>
#include<string.h>
#define BUFFER_SIZE 4096
#define MAX_PATTERN 256
int hex_to_int(char c){
    c = tolower(c);
    return ('0' <= c && c <= '9') ? c - '0' : ('a' <= c && c <= 'f') ? c - 'a' + 10 : -1;
}

int parse_pattern(const unsigned char *input, unsigned char *pattern, size_t *len){
    *len = 0;
    while(*input && *len < MAX_PATTERN){
        while(*input == ' ')
            input++;
        
        if (!isxdigit(input[0]) || (!isxdigit(input[1]))){
            return -1;
        }

        pattern[(*len)++] = (hex_to_int(input[0]) << 4) | (hex_to_int(input[1])); 
        input += 2;
    }
    return 0;
}

void search_pattern(const unsigned char *data, size_t data_len, const unsigned char *pattern, size_t pattern_len, size_t offset) {
    for (size_t i = 0; i <= data_len - pattern_len; i++)
        if (!memcmp(data + i, pattern, pattern_len))
            printf("Pattern found at offset: 0x%08X\n", offset + i);
}

int main(int argc, char **argv){
    if (argc != 3){
        fprintf(stderr, "Usage: %s <binary_file> <pattern>", argv[0]);
        return 1;
    }
    FILE *file;
    file = fopen(argv[1], "rb");
    if (file == NULL){
        fprintf(stderr, "Can not open file");
        return 1;
    }
    unsigned char pattern[MAX_PATTERN];
    size_t pattern_len = 0;
    if (parse_pattern(argv[2], pattern, &pattern_len)){
        fprintf(stderr, "Invalid pattern");
        fclose(file);
        return 1;
    }
    
    unsigned char buffer[BUFFER_SIZE];
    size_t bytes_read = 0;
    size_t offset = 0;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file))> 0){
        search_pattern(buffer, bytes_read, pattern, pattern_len, offset);
        offset += bytes_read;
    }

    fclose(file);
    return 0;
}
