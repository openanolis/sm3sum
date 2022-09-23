#ifndef SM3_H
#define SM3_H
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
/*
 * This header contains declearations of SM3 algorithim functions
 */
#define BLOCK_SIZE 512

// 36MB
#define BLOCK_BATCH_CNT 4 // 73728

#define BYTE_SIZE 8
#define IV0 0x7380166F
#define IV1 0x4914B2B9
#define IV2 0x172442D7
#define IV3 0xDA8A0600
#define IV4 0xA96F30BC
#define IV5 0x163138AA
#define IV6 0xE38DEE4D
#define IV7 0xB0FB0E4E 

#define PATH_LIMIT 1024 // adjust if needed
#define HASH_LIMIT 64 // adjust if needed

#define BSIZE 132
#define WORDSIZE 4
void sm3_padding(uint8_t *buf, size_t *bsize, size_t totsize);
void sm3_iterate(uint8_t *buf, size_t bsize);
void sm3_print(char *file_name);
void V_init();

/*
 * file_list is used for both directly given file names */
typedef struct file_list {
    struct file_list *next;
    char *file_name;
} file_list;

typedef struct {
    bool stdio;
    bool check_mode;
    bool bsd_tag;
    bool zero;
    bool ignore_missing;
    bool quiet;
    bool status;
    bool strict;
    bool warn;
    file_list head, *tail;
} sm3_arguments;

extern uint32_t V[8];

uint64_t local_to_be(uint64_t data);
uint32_t local_to_be32(uint32_t data);

#endif // SM3_H
