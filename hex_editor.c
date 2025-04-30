#include<stdio.h>
#include<stdlib.h>
#include<ctype.h>

# define BUFFER_SIZE 16
void print_hex_ascii(unsigned char *buffer, size_t bytes_read, size_t offset){
    printf("%04X: ", (unsigned int)offset);

    //print hex
    for (size_t i = 0; i < BUFFER_SIZE; i++){
        if (i < bytes_read){
            printf("%02X ", buffer[i]);
        }else{
            printf("  ");
        }
    }

    printf(" ");
    for (size_t i = 0; i < bytes_read; i++){
        if (isprint(buffer[i])){
            printf("%c", buffer[i]);
        }else{
            printf(".");
        }
    }
    printf("\n");
}

int main(int argc, char *argv[]){
    //Check argc
    if (argc != 2){
        fprintf(stderr, "Usage: %s <binary_file>\n", argv[0]);
    }

    FILE *file = fopen(argv[1], "rb");
    if(file == NULL){
       perror("Error opening file");
       return 1; 
    }

    unsigned char buffer[BUFFER_SIZE];
    size_t bytes_read;
    size_t offset = 0;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0){
        print_hex_ascii(buffer, bytes_read, offset);
        offset += bytes_read;
    }

    if(ferror(file)){
        perror("Error reading file");
        fclose(file);
        return 1;
    }

    fclose(file);
    return 0;
}
