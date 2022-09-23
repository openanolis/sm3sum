#ifndef FILE_HANDLER_H
#define FILE_HANDLER_H

#include <stdint.h>
#include <string.h>
#include "sm3.h"
#include <stdio.h>
typedef struct file_hash_pair{
    char *file_name;
    uint32_t expected_sm3[8];
    uint32_t calculated_sm3[8];
    struct file_hash_pair *next;
} file_sm3_pair;

extern sm3_arguments sm3_args;
extern file_sm3_pair hash_pair_head;
void parse_checklist(char *buf, size_t bsize);
void parse_checklist_init();
void parse_filelist();
size_t get_file_size(char *filename);
void read_and_calc(FILE *fp, size_t file_size);
void stdin_read_and_calc();
#endif // FILE_HANDLER_H