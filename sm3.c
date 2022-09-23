#include "sm3.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

uint64_t local_to_be(uint64_t data) {
#ifdef SM3_BIG_ENDIAN
    return data;
#else
    uint64_t ret;
    ret = (data >> 56) |
          ((data<<40) & 0x00FF000000000000UL) |
          ((data<<24) & 0x0000FF0000000000UL) |
          ((data<<8) & 0x000000FF00000000UL) |
          ((data>>8) & 0x00000000FF000000UL) |
          ((data>>24) & 0x0000000000FF0000UL) |
          ((data>>40) & 0x000000000000FF00UL) |
          (data << 56);
    return ret;
#endif // SM3_BIG_ENDIAN
}

uint32_t local_to_be32(uint32_t data) {
#ifdef SM3_BIG_ENDIAN
    return data;
#else
    uint32_t ret;
    ret = (data >> 24) |
          ((data<<8) & 0x00FF0000) |
          ((data>>8) & 0x0000FF00) |
          (data << 24);
    return ret;
#endif // SM3_BIG_ENDIAN
}

/*
 * Most machines that sm3sum intends to run on is little endian
 * However to be secure, check if we are wrong
 */
bool endian_check() {
    uint32_t n = 1;
    // little endian if true
    if(*(char *)&n == 1) {
        return true;
    } else {
        return false;
    }   
}

/*
 * buf: buffer that contains content, at least bsize + 2 * BLOCK_SIZE bits
 * bsize: buffer size in BITS
 * function: the first stage of sm3 algorithm
 */
void sm3_padding(uint8_t *buf, size_t *bsize, size_t tot_len) {
    // append one 1 bit
    size_t byte_offset = *bsize / 8;
    size_t byte_append = 1 << (7 - *bsize % 8);
    buf[byte_offset] |= byte_append;
    *bsize += 1;

    uint64_t *buf_64 = (uint64_t *)buf;
    uint64_t bsize_be = local_to_be(tot_len);
    if (*bsize % BLOCK_SIZE <= 448) {
        // size info suits well into the last block
        buf_64[*bsize / 512 * 8 + 7] = bsize_be;
        *bsize = ((*bsize / 512) + 1) * 512; // align to this block boundary
    } else {
        // adding a new block
        buf_64[*bsize / 512 * 8 + 15] = bsize_be;
        *bsize = ((*bsize / 512) + 2) * 512; // align to next block boundary
    }
#ifdef DEBUG
    /*
    for (int i = 0; i < (*bsize / 8); i++) {
        printf("%2x ", buf[i]);
        if (i % 32 == 31) {
            printf("\n");
        }
    }
    printf("\n");
    */
#endif // DEBUG
}


/*
 * cyclic left shift
 * expect local endian data
 */
uint32_t cls(uint32_t data, uint32_t shift) {
    uint32_t ret;
    ret = (data >> (32 - shift)) | (data << shift);
    return ret;
}

/*
 * FFj function, expect local endian but actually does not matter
 */
uint32_t FFj(uint32_t x, uint32_t y, uint32_t z, uint32_t j) {
    assert(j >= 0 && j < 64);
    if (j <= 15) {
        return x ^ y ^ z;
    } else {
        return (x & y) | (x & z) | (y & z);
    }
}

/*
 * GGj function, expect local endian but actually does not matter
 */
uint32_t GGj(uint32_t x, uint32_t y, uint32_t z, uint32_t j) {
    assert(j >= 0 && j < 64);
    if (j <= 15) {
        return x ^ y ^ z;
    } else {
        return (x & y) | ((~x) & z);
    }
}

/*
 * Tj function, return local endian data
 */
uint32_t Tj(uint32_t j) {
    assert(j >= 0 && j <= 63);
    if (j <= 15) return 0x79cc4519;
    else return 0x7a879d8a;
}

/*
 * P0 function, expect local endian
 */
uint32_t P0(uint32_t x) {
    return x ^ cls(x, 9) ^ cls(x, 17);
} 

/*
 * P1 function, expect local endian
 */
uint32_t P1(uint32_t x) {
    return x ^ cls(x, 15) ^ cls(x, 23);
} 

/*
 * generate W and W' (in big endian) from a 512-bit block
 * W: 0 to 67 W': 68 to 131
 */
uint32_t * sm3_word_gen(uint32_t *buf) {
    uint32_t *ret = (uint32_t *)malloc(BSIZE * WORDSIZE);
    for (int i = 0; i < 16; i++) {
        ret[i] = buf[i];
    }
    uint32_t p1_arg, wj_local;
    for (int i = 16; i < 68; i++) {
        // W_16 to W_67
        p1_arg = local_to_be32(ret[i - 16] ^ ret[i - 9]) ^ cls(local_to_be32(ret[i - 3]), 15);
        wj_local = P1(p1_arg) ^ cls(local_to_be32(ret[i - 13]), 7) ^ local_to_be32(ret[i - 6]);
        ret[i] = local_to_be32(wj_local);
    }
    for (int i = 0; i < 64; ++i) {
        // endian does not matter for xor
        ret[i + 68] = ret[i] ^ ret[i + 4];
    }
    return ret;
}


uint32_t V[8];
/*
 * There can be re-run, V should be able to be reset
 */
void V_init() {
    V[0] = local_to_be32(IV0);
    V[1] = local_to_be32(IV1);
    V[2] = local_to_be32(IV2);
    V[3] = local_to_be32(IV3);
    V[4] = local_to_be32(IV4);
    V[5] = local_to_be32(IV5);
    V[6] = local_to_be32(IV6);
    V[7] = local_to_be32(IV7);
}

void sm3_iterate(uint8_t *buf, size_t bsize) {
    // for (int i = 0; i < 8; i++) V[i] = local_to_be32(V[i]);
    // V[i] has correct IV in big endian now

    uint32_t A, B, C, D, E, F, G, H, SS1, SS2, TT1, TT2;
    // iterate to generate V_n
    for (int i = 0; i < bsize / BLOCK_SIZE; i++) {
        // generate W_i
        uint32_t *w_buf = sm3_word_gen((uint32_t *)(buf + i * BLOCK_SIZE / 8));
#ifdef DEBUG
        uint8_t *w_buf_8 = (uint8_t *)w_buf;
        printf("W array:\n");
        for (int i = 0; i < 68 * 4; i++) {
            printf("%2x", w_buf_8[i]);
            if (i % 4 == 3) printf(" ");
            if (i % 32 == 31) printf("\n");
        }
        printf("\nW' array:\n");
        for (int i = 0; i < 64 * 4; i++) {
            printf("%2x", w_buf_8[i + 68 * 4]);
            if (i % 4 == 3) printf(" ");
            if (i % 32 == 31) printf("\n");
        }
#endif // DEBUG
        // calculate V_i
        // note that we read big endian data, convert it to local endian, compute and just before write back, turn back to big endian
        A = local_to_be32(V[0]);
        B = local_to_be32(V[1]);
        C = local_to_be32(V[2]);
        D = local_to_be32(V[3]);
        E = local_to_be32(V[4]);
        F = local_to_be32(V[5]);
        G = local_to_be32(V[6]);
        H = local_to_be32(V[7]);
        for (int i = 0; i < 64; i++) {
            SS1 = cls(cls(A, 12) + E + cls(Tj(i), i), 7);
            SS2 = SS1 ^ cls(A, 12);
            TT1 = FFj(A, B, C, i) + D + SS2 + local_to_be32(w_buf[68 + i]);
            TT2 = GGj(E, F, G, i) + H + SS1 + local_to_be32(w_buf[i]);
            D = C;
            C = cls(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = cls(F, 19);
            F = E;
            E = P0(TT2);
#ifdef DEBUG
            printf("%d iter: A=%8x B=%8x C=%8x D=%8x E=%8x F=%8x G=%8x H=%8x\n", i, A, B, C, D, E, F, G, H);
#endif // DEBUG
        }
        A = local_to_be32(A);
        B = local_to_be32(B);
        C = local_to_be32(C);
        D = local_to_be32(D);
        E = local_to_be32(E);
        F = local_to_be32(F);
        G = local_to_be32(G);
        H = local_to_be32(H);
        V[0] = A ^ V[0];
        V[1] = B ^ V[1];
        V[2] = C ^ V[2];
        V[3] = D ^ V[3];
        V[4] = E ^ V[4];
        V[5] = F ^ V[5];
        V[6] = G ^ V[6];
        V[7] = H ^ V[7];



        free(w_buf);
    }
    
}


extern sm3_arguments sm3_args;
/*
 * function: print the sm3 result
 */
void sm3_print(char *file_name) {
    if (sm3_args.bsd_tag) {
        printf("SM3 (%s) = ", file_name);
    }
    for (int i = 0; i < 8; i++) {
        printf("%x", local_to_be32(V[i]));
    }
    if (!sm3_args.bsd_tag) {
        printf(" %s", file_name);
    }
    printf("\n");
}

/* 
 * buf: buffer that contains content
 * bsize: buffer size in BITS
 * function: main function of sm3 algorithm
 */
void sm3(uint8_t *buf, size_t *bsize) {
    sm3_padding(buf, bsize, *bsize);
    assert(*bsize % BLOCK_SIZE == 0); // must have been padded
    sm3_iterate(buf, *bsize);
}

