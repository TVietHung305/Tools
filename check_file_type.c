/*
Phân tích magic bytes
Mô tả: Viết chương trình đọc 4 byte đầu tiên của file nhị phân và xác định loại file dựa trên magic bytes.
*/

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdint.h>

typedef struct{
    unsigned char bytes[4];
    const char* filetype;
    size_t size;
}MagicBytes;


int main(int argc, char **argv){
    MagicBytes magicbytes[] = {
        {{0x4D, 0x5A, 0x90, 0x00}, "PE executable (MZ)", 2},               // PE/EXE/DLL
        {{0x7F, 0x45, 0x4C, 0x46}, "ELF (Linux executable)", 4},           // ELF
        {{0xCF, 0xFA, 0xED, 0xFE}, "Mach-O (macOS executable, 32-bit)", 4}, // Mach-O 32-bit
        {{0xCE, 0xFA, 0xED, 0xFE}, "Mach-O (macOS executable, 64-bit)", 4}, // Mach-O 64-bit
        {{0x25, 0x50, 0x44, 0x46}, "PDF document", 4},                     // PDF
        {{0x50, 0x4B, 0x03, 0x04}, "ZIP archive", 4},                      // ZIP/DOCX/XLSX/PPTX
        {{0x52, 0x61, 0x72, 0x21}, "RAR archive", 4},                      // RAR
        {{0xFF, 0xD8, 0xFF, 0xE0}, "JPEG image", 4},                       // JPEG/JPG
        {{0x89, 0x50, 0x4E, 0x47}, "PNG image", 4},                        // PNG
        {{0x47, 0x49, 0x46, 0x38}, "GIF image", 4},                        // GIF
        {{0x49, 0x44, 0x33, 0x03}, "MP3 audio", 3},                        // MP3
        {{0x52, 0x49, 0x46, 0x46}, "RIFF container (AVI/WAV)", 4},         // RIFF (AVI/WAV)
        {{0x38, 0x42, 0x50, 0x53}, "PSD image", 4},                        // PSD
        {{0x53, 0x51, 0x4C, 0x69}, "SQLite database", 4},                  // SQLite
        {{0x3C, 0x3F, 0x78, 0x6D}, "XML document", 4},                     // XML
        {{0x3C, 0x68, 0x74, 0x6D}, "HTML document", 4},                    // HTML
        {{0xCA, 0xFE, 0xBA, 0xBE}, "Java class file", 4},                  // Java class
        {{0x42, 0x5A, 0x68, 0x39}, "BZip2 archive", 4},                    // BZip2
        {{0x1F, 0x8B, 0x08, 0x00}, "GZIP archive", 4},                     // GZIP
        {{0x49, 0x49, 0x2A, 0x00}, "TIFF image (little endian)", 4},       // TIFF (little endian)
        {{0x4D, 0x4D, 0x00, 0x2A}, "TIFF image (big endian)", 4},          // TIFF (big endian)
        {{0x00, 0x00, 0x01, 0x00}, "ICO icon", 4},                         // ICO
        {{0x66, 0x74, 0x79, 0x70}, "MP4 video", 4},                        // MP4
        {{0x4F, 0x67, 0x67, 0x53}, "OGG audio", 4},                        // OGG
        {{0x1A, 0x45, 0xDF, 0xA3}, "WebM/MKV video", 4},                   // WebM/MKV
        {{0x75, 0x73, 0x74, 0x61}, "TAR archive", 4},                      // TAR
        {{0x4E, 0x45, 0x53, 0x1A}, "NES ROM", 4},                          // NES ROM
        {{0xD0, 0xCF, 0x11, 0xE0}, "MS Office document (DOC/XLS/PPT)", 4}, // MS Office legacy
        {{0x46, 0x4C, 0x56, 0x01}, "FLV video", 4}                         // FLV
    };

    int num_filetype = sizeof(magicbytes) / sizeof(MagicBytes);

    if (argc != 2){
        fprintf(stderr, "Usage: %s <binary_file>\n", argv[0]);
        return 1;
    }

    FILE *file;
    file = fopen(argv[1], "rb");
    if(file == NULL){
        fprintf(stderr, "Can not open file\n");
        return 1;
    }

    unsigned char buffer[4];
    size_t bytes_read = fread(buffer, 1, 4, file);

    if (bytes_read < 4){
        printf("Error: File is too small\n");
        fclose(file);
        return 1;
    }

    int found = 0;
    for(int i = 0; i < num_filetype; i++){
        if(memcmp(buffer, magicbytes[i].bytes, magicbytes[i].size) == 0){
            printf("File type: %s\n", magicbytes[i].filetype);
            found = 1;
        }
    }

    if (found == 0){
        printf("File type: Unknown\n");
    }

    fclose(file);
    return 0;

}
