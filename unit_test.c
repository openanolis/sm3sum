#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "sm3.h"
#include <stdio.h>
#include "file_handler.h"
    /*
 * This file contains tests for sm3 algorithm
 */

void sm3_padding_test() {
    // test case is from SM3 official document
    uint8_t *buf = (uint8_t *)malloc(2048);
    buf[0] = 0x61;
    buf[1] = 0x62;
    buf[2] = 0x63;
    size_t bsize = 3 * 8;
    sm3_padding(buf, &bsize, bsize);
    sm3_iterate(buf, bsize);
    free(buf);
}

void sm3_block_ext_test() {
    // test case from SM3 official document
    uint8_t *buf = (uint8_t *)malloc(2048);
    for (int i = 0; i < 16; i++) {
        buf[i * 4 + 0] = 0x61;
        buf[i * 4 + 1] = 0x62;
        buf[i * 4 + 2] = 0x63;
        buf[i * 4 + 3] = 0x64;
    }
    size_t bsize = 512;
    sm3_padding(buf, &bsize, bsize);
    sm3_iterate(buf, bsize);
    free(buf);
}

#include "file_handler.h"

void sm3_parse_checklist_test() {
    // test that checklist works properly
    extern file_sm3_pair hash_pair_head;
    sm3_args.bsd_tag = true;
    // BSD style
    char buf_bsd[] = "SM3 (a.out) = 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
    int size_bsd = strlen(buf_bsd);
    parse_checklist_init();
    parse_checklist(buf_bsd, size_bsd);
    printf("BSD style: file %s hash ", hash_pair_head.next->file_name);
    for (int i = 0; i < 8; i++) {
        printf("%x", hash_pair_head.next->expected_sm3[i]);
    }
    printf("\n");
    if (hash_pair_head.next->file_name != NULL) {
        free(hash_pair_head.next->file_name);
    }
    char buf_bsd_2[] = "SM3(a.out) = 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
    size_bsd = strlen(buf_bsd_2);
    parse_checklist_init();
    parse_checklist(buf_bsd_2, size_bsd);
    printf("BSD style: file %s hash ", hash_pair_head.next->file_name);
    for (int i = 0; i < 8; i++) {
        printf("%x", hash_pair_head.next->expected_sm3[i]);
    }
    printf("\n");
    if (hash_pair_head.next->file_name != NULL) {
        free(hash_pair_head.next->file_name);
    }

    // non-BSD style
     sm3_args.bsd_tag = false;
    char buf_gnu[] = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0 a.out";
    int size_gnu = strlen(buf_gnu);
    parse_checklist_init(); // note that it may leak memory under wrong cases, but should be fine during test
    parse_checklist(buf_gnu, size_gnu);
    printf("GNU style: file %s hash ", hash_pair_head.next->file_name);
    for (int i = 0; i < 8; i++) {
        printf("%x", hash_pair_head.next->expected_sm3[i]);
    }
    printf("\n");
    if (hash_pair_head.next->file_name != NULL) {
        free(hash_pair_head.next->file_name);
    }
}

void sm3_parse_filelist_test() {
    // test oridinary file parse
    extern void parse_arguments(int argc, char *argv[]);
    int argc = 3;
    char *argv[] = {"dontcare", "file1", "file2"};
    parse_arguments(argc, argv);
    file_list *file_ptr = sm3_args.head.next;
    while (file_ptr != NULL) {
        for (int i = 1; i < argc; i++) {
            if (strcmp(file_ptr->file_name, argv[i]) == 0) {
                // matched file name
                printf("Found matched filename %s\n", file_ptr->file_name);
                goto next;
            }
        }
        printf("Cannot find filename %s in arg info, exiting\n", file_ptr->file_name);
        next:
        file_ptr = file_ptr->next;
    }
}