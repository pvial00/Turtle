#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct turtle_state {
    uint32_t K[4][4];
    int v[4][4][32];
    uint32_t d[4];
    uint32_t last[4];
    uint32_t next[4];
    uint32_t rounds;
};

uint32_t swapbits(uint32_t r, int a, int b) {
    uint32_t x = (r >> a) & 1;
    uint32_t y = (r >> b) & 1;
    uint32_t z = (x ^ y);
    z = (z << a) | (z << b);
    return r ^ z;
}

uint32_t swap_encrypt(struct turtle_state *state, uint32_t r, int l, int round) {
   for (int i = 0; i < 31; i++) {
      r = swapbits(r, state->v[round][l][i], state->v[round][l][i+1]);
   }
   return r;
}

uint32_t swap_decrypt(struct turtle_state *state, uint32_t r, int l, int round) {
    for (int i = 31; i != 0; i--) {
        r = swapbits(r, state->v[round][l][i], state->v[round][l][i-1]);
    }
    return r;
}

uint32_t diffuse_encrypt(struct turtle_state *state, uint32_t r, int n) {
   r = (r + state->d[n]) & 0xFFFFFFFF;
   return r;
}

uint32_t diffuse_decrypt(struct turtle_state *state, uint32_t r, int n) {
    r = (r - state->d[n]) & 0xFFFFFFFF;
    return r;
}

void turtle_ksa(struct turtle_state *state, unsigned char * key, unsigned char * iv) {
    state->rounds = 4;
    state->last[0] = (iv[0] << 24) + (iv[1] << 16) + (iv[2] << 8) + iv[3];
    state->last[1] = (iv[4] << 24) + (iv[5] << 16) + (iv[6] << 8) + iv[7];
    state->last[2] = (iv[8] << 24) + (iv[9] << 16) + (iv[10] << 8) + iv[11];
    state->last[3] = (iv[12] << 24) + (iv[13] << 16) + (iv[14] << 8) + iv[15];

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
    for (int i = 0; i < 4; i++) {
        temp = (state->K[0][0] + state->K[0][1] + state->K[0][2] + state->K[0][3] + temp) & 0xFFFFFFFF;
        state->d[i] = temp;
    }
    for (int r = 0; r < 4; r++) {
        for (int l = 0; l < 4; l++) {
            for (int i = 0; i < 32; i++) {
                state->v[r][l][i] = i;
            }
        }
    }
    int t = 0;
    int j = 0;
    for (int r = 0; r < 4; r++) {
        for (int l = 0; l < 4; l++) {
            for (int i = 0; i < 768; i++) {
                j = (j + key[i % 16]) & 0x1F;
                key[i % 16] = (key[i % 16] + key[(i + 1) % 16]) & 0xFF;
                t = state->v[r][l][i & 0x1F];
                state->v[r][l][i & 0x1F] = state->v[r][l][j];
                state->v[r][l][j] = t;
            }
        }
    }
}

void turtle_cbc_encrypt(unsigned char * msg, int msglen, unsigned char * key, int keylen, unsigned char * iv, int ivlen, int extrabytes) {
    struct turtle_state state;
    uint32_t block[4];
    int blocks = msglen / 16;
    int c = 0;
    int i;
    turtle_ksa(&state, key, iv);
    for (i = 0; i < blocks; i++) {
	if (i == (blocks - 1)) {
            for (int p = 0; p < extrabytes; p++) {
                msg[(msglen-1)-p] = (unsigned char *)extrabytes;
	    }
	}
	 
        block[0] = (msg[c] << 24) + (msg[c+1] << 16) + (msg[c+2] << 8) + msg[c+3];
        block[1] = (msg[c+4] << 24) + (msg[c+5] << 16) + (msg[c+6] << 8) + msg[c+7];
        block[2] = (msg[c+8] << 24) + (msg[c+9] << 16) + (msg[c+10] << 8) + msg[c+11];
        block[3] = (msg[c+12] << 24) + (msg[c+13] << 16) + (msg[c+14] << 8) + msg[c+15];

	block[0] = block[0] ^ state.last[0];
	block[1] = block[1] ^ state.last[1];
	block[2] = block[2] ^ state.last[2];
	block[3] = block[3] ^ state.last[3];

        for (int r = 0; r < state.rounds; r++) {
            for (int g = 0; g < 4; g++) {
                block[g] = swap_encrypt(&state, block[g], g, r);
                block[g] = block[g] ^ block[(g - 1) & 0x03];
                block[g] = block[g] ^ state.K[r][g];
            }
            for (int g = 0; g < 4; g++) {
                block[g] = diffuse_encrypt(&state, block[g], r);
            }
        }


	state.last[0] = block[0];
	state.last[1] = block[1];
	state.last[2] = block[2];
	state.last[3] = block[3];

        msg[c+3] = (block[0] & 0x000000FF);
        msg[c+2] = (block[0] & 0x0000FF00) >> 8;
        msg[c+1] = (block[0] & 0x00FF0000) >> 16;
        msg[c] = (block[0] & 0xFF000000) >> 24;
        msg[c+7] = (block[1] & 0x000000FF);
        msg[c+6] = (block[1] & 0x0000FF00) >> 8;
        msg[c+5] = (block[1] & 0x00FF0000) >> 16;
        msg[c+4] = (block[1] & 0xFF000000) >> 24;
        msg[c+11] = (block[2] & 0x000000FF);
        msg[c+10] = (block[2] & 0x0000FF00) >> 8;
        msg[c+9] = (block[2] & 0x00FF0000) >> 16;
        msg[c+8] = (block[2] & 0xFF000000) >> 24;
        msg[c+15] = (block[3] & 0x000000FF);
        msg[c+14] = (block[3] & 0x0000FF00) >> 8;
        msg[c+13] = (block[3] & 0x00FF0000) >> 16;
        msg[c+12] = (block[3] & 0xFF000000) >> 24;
        c += 16;
    }
}

int turtle_cbc_decrypt(unsigned char * msg, int msglen, unsigned char * key, int keylen, unsigned char * iv, int ivlen) {
    struct turtle_state state;
    uint32_t block[4];
    int blocks = msglen / 16;
    int c = 0;
    int i;
    turtle_ksa(&state, key, iv);
    for (i = 0; i < blocks; i++) {
        block[0] = (msg[c] << 24) + (msg[c+1] << 16) + (msg[c+2] << 8) + msg[c+3];
        block[1] = (msg[c+4] << 24) + (msg[c+5] << 16) + (msg[c+6] << 8) + msg[c+7];
        block[2] = (msg[c+8] << 24) + (msg[c+9] << 16) + (msg[c+10] << 8) + msg[c+11];
        block[3] = (msg[c+12] << 24) + (msg[c+13] << 16) + (msg[c+14] << 8) + msg[c+15];
        
	state.next[0] = block[0];
	state.next[1] = block[1];
	state.next[2] = block[2];
	state.next[3] = block[3];

        for (int r = (state.rounds -1); r != -1; r--) {
            for (int g = 0; g < 4; g++) {
                block[g] = diffuse_decrypt(&state, block[g], r);
            }
            for (int g = 4; g --> 0;) {
                block[g] = block[g] ^ state.K[r][g];
                block[g] = block[g] ^ block[(g - 1) & 0x03];
                block[g] = swap_decrypt(&state, block[g], g, r);
            }
        }

	block[0] = block[0] ^ state.last[0];
	block[1] = block[1] ^ state.last[1];
	block[2] = block[2] ^ state.last[2];
	block[3] = block[3] ^ state.last[3];
	state.last[0] = state.next[0];
	state.last[1] = state.next[1];
	state.last[2] = state.next[2];
	state.last[3] = state.next[3];
        
        msg[c+3] = (block[0] & 0x000000FF);
        msg[c+2] = (block[0] & 0x0000FF00) >> 8;
        msg[c+1] = (block[0] & 0x00FF0000) >> 16;
        msg[c] = (block[0] & 0xFF000000) >> 24;
        msg[c+7] = (block[1] & 0x000000FF);
        msg[c+6] = (block[1] & 0x0000FF00) >> 8;
        msg[c+5] = (block[1] & 0x00FF0000) >> 16;
        msg[c+4] = (block[1] & 0xFF000000) >> 24;
        msg[c+11] = (block[2] & 0x000000FF);
        msg[c+10] = (block[2] & 0x0000FF00) >> 8;
        msg[c+9] = (block[2] & 0x00FF0000) >> 16;
        msg[c+8] = (block[2] & 0xFF000000) >> 24;
        msg[c+15] = (block[3] & 0x000000FF);
        msg[c+14] = (block[3] & 0x0000FF00) >> 8;
        msg[c+13] = (block[3] & 0x00FF0000) >> 16;
        msg[c+12] = (block[3] & 0xFF000000) >> 24;
        c += 16;

	if (i == (blocks - 1)) {
            int count = 0;
	    int padcheck = msg[msglen - 1];
	    int g = msglen - 1;
	    for (int p = 0; p < padcheck; p++) {
                if ((int)msg[g] == padcheck) {
                    count += 1;
		}
		g = g - 1;
            }
            if (count == padcheck) {
                return count;
            }
            else {
                return 0;
            }
	}
    }
}
