#include "file_handler.h"
#include <sys/stat.h>
#include <ctype.h>
#include <memory.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "sm3.h"
#include <assert.h>

file_sm3_pair hash_pair_head, *hash_pair_tail;

/*
 * initialize link list head
 */
void parse_checklist_init() {
    hash_pair_head.next = NULL;
    hash_pair_tail = &hash_pair_head;
}

/*
 * convert sm3 string to int array
 * sm3_str: char array that contains sm3 string
 * return: uint32_t array
 */
uint32_t *sm3str2int(char *sm3_str) {
    uint32_t *ret = malloc(sizeof(uint32_t) * 8);
    for (int i = 0; i < 8; i++) {
        uint32_t result = 0;
        for (int j = 0; j < 8; j++) {
            uint32_t tmp = tolower(sm3_str[i * 8 + j]);
            result = result << 4 | (isdigit(tmp) ? tmp - '0' : tmp - 'a' + 10);
        }
        ret[i] = local_to_be32(result);
    }
    return ret;
}

/*
 * parse the output of sm3sum for the purpose of verifying
 * buf: a buffer that contains the output of a previous sm3sum
 * bsize: size of the buffer in bytes
*/
void parse_checklist(char *buf, size_t bsize) {
    // note that BSD format and default format differs here
    char *filename_str, *hash_str;
    filename_str = (char *)malloc(PATH_LIMIT + 1);
    hash_str = (char *)malloc(HASH_LIMIT + 1);
    int readin;
    if (sm3_args.bsd_tag) {
        // SM3 (FILENAME) = HASH
        readin = sscanf(buf, "SM3 %1024s = %64s", filename_str, hash_str);
        memmove(filename_str, filename_str+1, strlen(filename_str)); // remove (
        filename_str[strlen(filename_str) - 1] = 0; // remove )
    } else {
        // HASH FILENAME
        readin = sscanf(buf, "%64s%1024s", hash_str, filename_str);
    }
    if (readin < 2) {
        // format error
        printf("File list illgal format error\n");
        exit(1);
    }

    if (strcmp(filename_str, "-") != 0) {
        file_sm3_pair *new_file_pair = malloc(sizeof(file_sm3_pair));
        new_file_pair->next = NULL;
        new_file_pair->file_name = filename_str;
        uint32_t *expected = sm3str2int(hash_str);
        memcpy(new_file_pair->expected_sm3, expected, sizeof(uint32_t) * 8);
        free(expected);
        hash_pair_tail->next = new_file_pair;
        hash_pair_tail = new_file_pair;
    }

    free(hash_str);
}


/*
 * get the file size in bytes
 * filename: file name in char array
 * return: file size in bytes
 */
size_t get_file_size(char *filename) {
    struct stat st;
    stat(filename, &st);
    return st.st_size;
}

/*
 * parse the input of sm3sum if check mode is enabled
 */
void parse_filelist() {
    FILE *check_file;
    char *check_buf = (char *)malloc(PATH_LIMIT + HASH_LIMIT + 15);
    size_t buf_len;
    if (sm3_args.check_mode) {
        parse_checklist_init();
        // only update file name-hash pair in check mode
        file_list *file_ptr = sm3_args.head.next;
        while (file_ptr != NULL) {
            if (1/*access(file_ptr->file_name, R_OK)*/) {
                // we are able to read from this file
                check_file = fopen(file_ptr->file_name, "r");
                while (fgets(check_buf, PATH_LIMIT + HASH_LIMIT + 10, check_file) != NULL) {
                    // each line need to be parsed
                    buf_len = strlen(check_buf);
                    parse_checklist(check_buf, buf_len);
                }
                fclose(check_file);
            } else {
                // cannot read file
                printf("Cannot access file %s, either non-existing or not readable\n", file_ptr->file_name);
            }
            file_ptr = file_ptr->next;
        }

    }
    free(check_buf);
    return ;
}

/*
 * fp: the FILE pointer of data to be calculated
 * file_size: the file size in bits
 */
void read_and_calc(FILE *fp, size_t file_size) {
    // block size: 36MB + 1 block (for padding)
    uint8_t *buf = (uint8_t *)malloc((BLOCK_BATCH_CNT * 2) * BLOCK_SIZE);
    size_t calculated = 0;
    size_t read_succ;
    V_init();
    while (calculated + (BLOCK_BATCH_CNT + 1)* BLOCK_SIZE <= file_size) {
        // read aligned block but leave the last one
        read_succ = fread(buf, BLOCK_BATCH_CNT * BLOCK_SIZE / 8, 1, fp);
        assert(read_succ);
        // does not padding
        sm3_iterate(buf, BLOCK_BATCH_CNT * BLOCK_SIZE);
        calculated += BLOCK_SIZE * BLOCK_BATCH_CNT;
    }
    #ifdef DEBUG
    printf("tail begin\n");
    #endif // DEBUG

    // may not occupy full space, needs clean up
    memset(buf, 0, (BLOCK_BATCH_CNT * 2) * BLOCK_SIZE);
    read_succ = fread(buf, file_size - calculated, 1, fp);
    size_t final_size = file_size - calculated;
    sm3_padding(buf, &final_size, file_size);
    assert(final_size % BLOCK_SIZE == 0);
    // size_t final_block_size = final_size - calculated;
    sm3_iterate(buf, final_size);
    free(buf);
}

void stdin_read_and_calc() {
    // stdin does not ensure size
    // may end at any point
    uint8_t *buf = (uint8_t *)malloc(2 * BLOCK_SIZE);
    size_t calculated = 0;
    size_t offset = 0;
    V_init();
    int c = getchar();
    while (c != EOF) {
        buf[offset] = c;
        ++calculated;
        ++offset;
        c = getchar();
        if (offset == BLOCK_SIZE / 8 && c != EOF) {
            offset = 0;
            // ready to calculate
            sm3_iterate(buf, BLOCK_SIZE);
        }
    }
    memset(buf + offset, 0, 2 * BLOCK_SIZE - offset);
    offset *= 8;
    sm3_padding(buf, &offset, calculated * 8);
    sm3_iterate(buf, offset);
    free(buf);
}