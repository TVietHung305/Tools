/*
Đếm và trích xuất chuỗi ASCII
Mô tả: Viết chương trình đọc một file nhị phân và trích xuất tất cả các chuỗi ASCII (chuỗi ký tự in được dài ít nhất 4 ký tự).
Hướng dẫn:
    Đọc file theo từng byte bằng fread.
    Khi gặp ký tự in được (isprint), lưu vào buffer tạm.
    Nếu chuỗi dài ≥ 4 ký tự và kết thúc bằng ký tự không in được, in chuỗi và offset.
    Ví dụ đầu ra:
        Offset 0x0004: "This program"
        Offset 0x0020: "MZ"
Mở rộng:
    Hỗ trợ trích xuất chuỗi Unicode (UTF-16).
    Lưu các chuỗi vào file text riêng để phân tích sau.
Kỹ năng: File I/O, xử lý chuỗi, offset tracking.
Ứng dụng: Trích xuất chuỗi từ mã độc để tìm IOCs (như URL, tên file).
*/
#include<stdio.h>
#include<stdlib.h>
#include<stdbool.h>
#include<ctype.h>
#include<string.h>

#define MIN_STRING_LENGTH 4
#define BUFFER_SIZE 1024

bool is_printable(unsigned char c){
    return isprint(c);
}

void print_string(unsigned char *buffer, size_t len, long offset){
    printf("Offset 0x%04X: \"", offset - len);
    for (size_t i = 0; i < len; i++){
        printf("%c", buffer[i]);
    }
    printf("\"\n");
}

void save_string_to_file(FILE *output_file, unsigned char *buffer, size_t length, long offset){
    if (output_file != NULL){
        fprintf(output_file, "0x%04X: \"", offset-length);
        for (size_t i = 0; i < length; i++){
            fprintf(output_file, "%c", buffer[i]);
        }
        fprintf(output_file, "\"\n");
    }
}

int main(int argc, char*argv[]){
    FILE *input_file;
    FILE *output_file = NULL;
    unsigned char byte; 
    long current_offset = 0;
    bool in_string = false;
    long string_start_offset = 0;
    unsigned char buffer[BUFFER_SIZE];
    size_t buffer_index = 0;

    if (argc < 2 || argc > 3){
        fprintf(stderr, "Usage: %s <input_file> [<output_file>]", argv[0]);
        return 1;
    }

    input_file = fopen(argv[1], "rb");
    if (input_file == NULL){
        fprintf(stderr, "Cannot open file!");
        return 1;
    }

    if (argc == 3){
        output_file = fopen(argv[2], "w");
        if (output_file == NULL){
            fprintf(stderr, "Can not open the output file!");
            fclose(input_file);
            return 1;
        }
    }

    while (fread(&byte, 1, 1, input_file) == 1){
        current_offset++;
        
        if(is_printable(byte)){

            if(!in_string){
                in_string = true;
                string_start_offset = current_offset;
            }

            buffer[buffer_index++] = byte;

            if(buffer_index >= BUFFER_SIZE - 1){
                if(buffer_index >= MIN_STRING_LENGTH){
                    print_string(buffer, buffer_index, current_offset);
                    save_string_to_file(output_file, buffer, buffer_index, current_offset);
                }
                buffer_index = 0;
                in_string = false;
            }
        } else{
            
            if (in_string && buffer_index >= MIN_STRING_LENGTH){
                print_string(buffer, buffer_index, current_offset);
                save_string_to_file(output_file, buffer, buffer_index, current_offset);
            }

            buffer_index = 0;
            in_string = false;
        }
    }

    if (in_string && buffer_index > MIN_STRING_LENGTH){
        print_string(buffer, buffer_index, current_offset);
        save_string_to_file(output_file, buffer, buffer_index, current_offset);
    }

    fclose(input_file);
    if(output_file != NULL){
        fclose(output_file);
    }
    return 0;
}