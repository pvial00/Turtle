#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "ganja.c"
#include "dyefamily.c"

struct turtle_state {
    uint32_t K[4][4];
    int v[4][32];
    uint32_t d;
};

uint32_t swapbits(uint32_t r, int a, int b) {
    uint32_t x = (r >> a) & 1;
    uint32_t y = (r >> b) & 1;
    uint32_t z = (x ^ y);
    z = (z << a) | (z << b);
    return r ^ z;
}

uint32_t swap_encrypt(struct turtle_state *state, uint32_t r, int l) {
   for (int i = 0; i < 31; i++) {
      r = swapbits(r, state->v[l][i], state->v[l][i+1]);
   }
   return r;
}

uint32_t swap_decrypt(struct turtle_state *state, uint32_t r, int l) {
    for (int i = 31; i != 0; i--) {
        r = swapbits(r, state->v[l][i], state->v[l][i-1]);
    }
    return r;
}

uint32_t diffuse_encrypt(struct turtle_state *state, uint32_t r) {
   r = (r + state->d) & 0xFFFFFFFF;
   return r;
}

uint32_t diffuse_decrypt(struct turtle_state *state, uint32_t r) {
    r = (r - state->d) & 0xFFFFFFFF;
    return r;
}

void ksa(struct turtle_state *state, unsigned char * key) {
    state->K[0][0] = (key[0] << 24) + (key[1] << 16) + (key[2] << 8) + key[3];
    state->K[0][1] = (key[4] << 24) + (key[5] << 16) + (key[6] << 8) + key[7];
    state->K[0][2] = (key[8] << 24) + (key[9] << 16) + (key[10] << 8) + key[11];
    state->K[0][3] = (key[12] << 24) + (key[13] << 16) + (key[14] << 8) + key[15];
    
    uint32_t temp = 0x00000001;
    temp = (state->K[0][0] + state->K[0][1] + state->K[0][2] + state->K[0][3] + temp) & 0xFFFFFFFF;
    for (int i = 0; i < 4; i++) {
        for (int l = 0; l < 4; l++) {
            temp = (state->K[0][0] + state->K[0][1] + state->K[0][2] + state->K[0][3] + temp) & 0xFFFFFFFF;
            state->K[i][l] = temp;
        }
    }
    temp = (state->K[0][0] + state->K[0][1] + state->K[0][2] + state->K[0][3] + temp) & 0xFFFFFFFF;
    state->d = temp;
    for (int l = 0; l < 4; l++) {
        for (int i = 0; i < 32; i++) {
            state->v[l][i] = i;
        }
    }
    int t = 0;
    int j = 0;
    for (int l = 0; l < 4; l++) {
        for (int i = 0; i < 768; i++) {
            j = (j + key[i % 16]) & 0x1F;
            key[i % 16] = (key[i % 16] + key[(i + 1) % 16]) & 0xFF;
            t = state->v[l][i & 0x1F];
            state->v[l][i & 0x1F] = state->v[l][j];
            state->v[l][j] = t;
        }
    }
    
}

int main(int arc, char *argv[]) {
    unsigned char * key[16] = {0};
    FILE *outfile, *infile;
    uint8_t k[16];
    uint32_t block[4];
    uint32_t last[4];
    uint32_t next[4];
    struct turtle_state state;
    int iv_length = 16;
    int keylen = 16;
    int rounds = 4;
    unsigned char iv[iv_length];
    int c = 0;
    char *mode = argv[1];
    char *inf = argv[2];
    char *outf = argv[3];
    char *password = argv[4];
    ganja_kdf(password, strlen(password), key, 10000, keylen, "WildLFSRCipherv1");
    ksa(&state, key);
    int v = 16;
    int x, i;
    int t = 0;
    infile = fopen(inf, "rb");
    fseek(infile, 0, SEEK_END);
    long fsize = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    unsigned char data[v];
    outfile = fopen(outf, "wb");
    if (strcmp(mode, "e") == 0) {
        int blocks = fsize / 16;
        int fsize_extra = fsize % 16;
        if (fsize_extra != 0) {
            blocks += 1;
        }
        wrzeszcz_random(&iv, iv_length);
        fwrite(iv, 1, iv_length, outfile);
        block[0] = (iv[0] << 24) + (iv[1] << 16) + (iv[2] << 8) + iv[3];
        block[1] = (iv[4] << 24) + (iv[5] << 16) + (iv[6] << 8) + iv[7];
        block[2] = (iv[8] << 24) + (iv[9] << 16) + (iv[10] << 8) + iv[11];
        block[3] = (iv[12] << 24) + (iv[13] << 16) + (iv[14] << 8) + iv[15];
        for (i = 0; i < (blocks); i++) {
            fread(data, 1, v, infile);
            for (int r = 0; r < rounds; r++) {
                for (int g = 0; g < 4; g++) {
                    block[g] = swap_encrypt(&state, block[g], g);
                    block[g] = block[g] ^ block[(g - 1) & 0x03];
                    block[g] = block[g] ^ state.K[r][g];
                }
		for (int g = 0; g < 4; g++) {
                    block[g] = diffuse_encrypt(&state, block[g]);
                }
            }
            k[3] = (block[0] & 0x000000FF);
            k[2] = (block[0] & 0x0000FF00) >> 8;
            k[1] = (block[0] & 0x00FF0000) >> 16;
            k[0] = (block[0] & 0xFF000000) >> 24;
            k[7] = (block[1] & 0x000000FF);
            k[6] = (block[1] & 0x0000FF00) >> 8;
            k[5] = (block[1] & 0x00FF0000) >> 16;
            k[4] = (block[1] & 0xFF000000) >> 24;
            k[11] = (block[2] & 0x000000FF);
            k[10] = (block[2] & 0x0000FF00) >> 8;
            k[9] = (block[2] & 0x00FF0000) >> 16;
            k[8] = (block[2] & 0xFF000000) >> 24;
            k[15] = (block[3] & 0x000000FF);
            k[14] = (block[3] & 0x0000FF00) >> 8;
            k[13] = (block[3] & 0x00FF0000) >> 16;
            k[12] = (block[3] & 0xFF000000) >> 24;
            if (i == (blocks - 1) && (fsize_extra != 0)) {
                v = fsize_extra; }
            for (int x = 0; x < v; x++) {
                data[x] = data[x] ^ k[x];
            }
            fwrite(data, 1, v, outfile);
        }
    }
    else if(strcmp(mode, "d") == 0) {
        int blocks = (fsize - iv_length) / 16;
        int fsize_extra = (fsize - iv_length) % 16;
        if (fsize_extra != 0) {
            blocks += 1;
        }
        fread(iv, 1, iv_length, infile);
        block[0] = (iv[0] << 24) + (iv[1] << 16) + (iv[2] << 8) + iv[3];
        block[1] = (iv[4] << 24) + (iv[5] << 16) + (iv[6] << 8) + iv[7];
        block[2] = (iv[8] << 24) + (iv[9] << 16) + (iv[10] << 8) + iv[11];
        block[3] = (iv[12] << 24) + (iv[13] << 16) + (iv[14] << 8) + iv[15];
        for (i = 0; i < blocks; i++) {
            fread(data, 1, v, infile);
            for (int r = 0; r < rounds; r++) {
                for (int g = 0; g < 4; g++) {
                    block[g] = swap_encrypt(&state, block[g], g);
                    block[g] = block[g] ^ block[(g - 1) & 0x03];
                    block[g] = block[g] ^ state.K[r][g];
                }
		for (int g = 0; g < 4; g++) {
                    block[g] = diffuse_encrypt(&state, block[g]);
                }
            }
            k[3] = (block[0] & 0x000000FF);
            k[2] = (block[0] & 0x0000FF00) >> 8;
            k[1] = (block[0] & 0x00FF0000) >> 16;
            k[0] = (block[0] & 0xFF000000) >> 24;
            k[7] = (block[1] & 0x000000FF);
            k[6] = (block[1] & 0x0000FF00) >> 8;
            k[5] = (block[1] & 0x00FF0000) >> 16;
            k[4] = (block[1] & 0xFF000000) >> 24;
            k[11] = (block[2] & 0x000000FF);
            k[10] = (block[2] & 0x0000FF00) >> 8;
            k[9] = (block[2] & 0x00FF0000) >> 16;
            k[8] = (block[2] & 0xFF000000) >> 24;
            k[15] = (block[3] & 0x000000FF);
            k[14] = (block[3] & 0x0000FF00) >> 8;
            k[13] = (block[3] & 0x00FF0000) >> 16;
            k[12] = (block[3] & 0xFF000000) >> 24;
            if (i == (blocks - 1) && (fsize_extra != 0)) {
                v = fsize_extra; }
            for (int x = 0; x < v; x++) {
                data[x] = data[x] ^ k[x];
            }
            fwrite(data, 1, v, outfile);
        }
    }
    fclose(outfile);
    fclose(outfile);
    fclose(infile);
}
