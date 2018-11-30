#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char *bluedye_crypt(unsigned char *data, unsigned char *key, unsigned char *nonce, long datalen, int keylen, int noncelen) {
    int k[32] = {0};
    int s[256];
    int temp;
    int output;
    int c;
    int j = 0;
    int i = 0;
    for (c = 0; c < 256; c++) {
        s[c] = c;
    }
    for (c=0; c < keylen; c++) {
        k[c % keylen] = (k[c % keylen] + key[c % keylen]) & 0xff;
        j = (j + k[c % keylen]) & 0xff; }
    for (c = 0; c < 768; c++) {
        k[c % keylen] = (k[c % keylen] + j) & 0xff;
        j = (j + k[c % keylen] + c) & 0xff; }
        temp = s[c & 0xff];
	s[c & 0xff] = s[j];
	s[j] = temp;
    for (c = 0; c < noncelen; c++) {
        k[c % keylen] = (k[c % keylen] + nonce[c]) & 0xff;
        j = (j + k[c % keylen]) & 0xff; }
    for (c = 0; c < 768; c++) {
        k[c % keylen] = (k[c % keylen] + j) & 0xff;
        j = (j + k[c % keylen] + c) & 0xff; }
        temp = s[c & 0xff];
	s[c & 0xff] = s[j];
	s[j] = temp;

   c = 0;
   for (int x = 0; x < datalen; x++) {
       k[i] = (k[i] + k[(i + 1) % keylen] + j) & 0xff;
       j = (j + k[i] + c) & 0xff;
       temp = s[c];
       s[c] = s[j];
       s[j] = temp;
       output = s[j] ^ k[i];
       data[x] = data[x] ^ output;
       c = (c + 1) & 0xff;
       i = (i + 1) % keylen;
   } 
}

unsigned char * bluedye_kdf (unsigned char *password, unsigned char *key, unsigned char *salt, int iterations, int keylen) {
    for (int x = 0; x < keylen; x++) {
        key[x] = 0;
    }
    int n = 0;
    for (int x = 0; x < strlen(password); x++) {
        key[n] = (key[n] + password[x]) % 256;
        n = (n + 1) % keylen;
    }
    int kdf_k[keylen];
    for (int x = 0; x < keylen; x++) {
        kdf_k[x] = 0;
    }
    int z[256];
    int tmp;
    int kdf_out;
    int t = 0;
    int r = 0;
    for (n = 0; n < 256; n++) {
        z[n] = n;
    }
    for (n=0; n < keylen; n++) {
        kdf_k[n % keylen] = (kdf_k[n % keylen] + key[n % keylen]) & 0xff;
        t = (t + kdf_k[n % keylen]) & 0xff; }
    for (n = 0; n < 768; n++) {
        kdf_k[n % keylen] = (kdf_k[n % keylen] + t) & 0xff;
        t = (t + kdf_k[n % keylen]) & 0xff; }
        tmp = z[n % 256];
	z[n % 256] = z[t];
	z[t] = tmp;
    int saltlen = sizeof(salt);
    for (n = 0; n < keylen; n++) {
        kdf_k[n] = (kdf_k[n] + salt[n % saltlen]) & 0xff;
        t = (t + kdf_k[n]) & 0xff; }
    for (n = 0; n < 768; n++) {
        kdf_k[n % keylen] = (kdf_k[n % keylen] + t) & 0xff;
        t = (t + kdf_k[n % keylen]) & 0xff; }
        tmp = z[n % 256];
	z[n % 256] = z[t];
	z[t] = tmp;

    n = 0;
    for (int x = 0; x < (keylen * iterations); x++) {
       kdf_k[r] = (kdf_k[r] + kdf_k[(r + 1) % keylen] + t) & 0xff;
       t = (t + kdf_k[r] + n) & 0xff;
       kdf_out = z[t] ^ kdf_k[r];
       key[r] = (unsigned char)key[r] ^ kdf_k[r];
       n = (n + 1) & 0xff;
       r = (r + 1) % keylen;
       tmp = z[n];
       z[n] = z[t];
       z[t] = tmp;
    }
}

unsigned char * bluedye_random (unsigned char *buf, int num_bytes) {
    int keylen = 32;
    int noncelen = 16;
    unsigned char *key[keylen];
    unsigned char *nonce[noncelen];
    FILE *randfile;
    randfile = fopen("/dev/urandom", "rb");
    fread(nonce, noncelen, 1, randfile);
    fread(key, keylen, 1, randfile);
    fclose(randfile);
    bluedye_crypt(buf, key, nonce, num_bytes, keylen, noncelen);
}

unsigned char * reddye_kdf (unsigned char *password, unsigned char *key, unsigned char *salt, int iterations, int keylen) {
    for (int x = 0; x < keylen; x++) {
        key[x] = 0;
    }
    int n = 0;
    for (int x = 0; x < strlen(password); x++) {
        key[n] = (key[n] + password[x]) % 256;
        n = (n + 1) % keylen;
    }
    int kdf_k[256];
    for (int x = 0; x < 256; x++) {
        kdf_k[x] = 0;
    }
    int t = 0;
    int r = 0;
    int d = 256 - keylen;
    int y = 256 / 2;
    int out;
    for (n=0; n < keylen; n++) {
        kdf_k[n % keylen] = (kdf_k[n % keylen] + key[n % keylen]) & 0xff;
        t = (t + kdf_k[n % keylen]) & 0xff; }
    for (n = 0; n < 256; n++) {
        kdf_k[n % keylen] = (kdf_k[n % keylen] + t) & 0xff;
        t = (t + kdf_k[n % keylen]) & 0xff; }
    int saltlen = sizeof(salt);
    for (n = 0; n < keylen; n++) {
        kdf_k[n] = (kdf_k[n] + salt[n % saltlen]) & 0xff;
        t = (t + kdf_k[n]) & 0xff; }
    for (n = 0; n < 256; n++) {
        kdf_k[n % keylen] = (kdf_k[n % keylen] + t) & 0xff;
        t = (t + kdf_k[n % keylen]) & 0xff; }
    for (n = 0; n < d; n++) {
        kdf_k[n+keylen] = (kdf_k[n] + kdf_k[(n + 1) % d] + t) & 0xff;
	t = (t + kdf_k[n % d] + n) & 0xff; }
    for (n = 0; n < 256; n++) {
        kdf_k[n] = (kdf_k[n] + kdf_k[(n + y) & 0xff] + t) & 0xff;
	t = (t + kdf_k[n] + n) & 0xff; }

    n = 0;
    for (int x = 0; x < (256 * iterations); x++) {
       kdf_k[r] = (kdf_k[r] + kdf_k[(r + 1) % keylen] + t) & 0xff;
       t = (t + kdf_k[r] + n) & 0xff;
       out = ((t + kdf_k[r]) & 0xff) ^ kdf_k[r];
       key[r] = (unsigned char)key[r] ^ out;
       n = (n + 1) & 0xff;
       r = (r + 1) % keylen;
    }
}

unsigned char *wrzeszcz_crypt(unsigned char *data, unsigned char *key, unsigned char *nonce, long datalen, int keylen, int noncelen) {
    int k[256] = {0};
    int s[256];
    int temp;
    int output;
    int c;
    int j = 0;
    int i = 0;
    int diff = 256 - keylen;
    for (c = 0; c < 256; c++) {
        s[c] = c;
    }
    for (c=0; c < keylen; c++) {
        k[c % keylen] = (k[c % keylen] + key[c % keylen]) & 0xff;
        j = (j + k[c % keylen]) & 0xff; }
    for (c = 0; c < 768; c++) {
        k[c % keylen] = (k[c % keylen] + j) & 0xff;
        j = (j + k[c % keylen] + c) & 0xff; }
        temp = s[c & 0xff];
	s[c & 0xff] = s[j];
	s[j] = temp;
    for (c = 0; c < noncelen; c++) {
        k[c] = (k[c] + nonce[c]) & 0xff;
        j = (j + k[c]) & 0xff; }
    for (c = 0; c < 768; c++) {
        k[c % keylen] = (k[c % keylen] + j) & 0xff;
        j = (j + k[c % keylen] + c) & 0xff; }
        temp = s[c & 0xff];
	s[c & 0xff] = s[j];
	s[j] = temp;
    for (c = 0; c < diff; c++) {
        k[c+keylen] = (k[c] + k[(c + 1) % diff] + j + s[j]) & 0xff;
	j = (j + k[c % diff] + s[c] + c) & 0xff;
        temp = s[c];
        s[c & 0xff] = s[j];
        s[j] = temp; }

   c = 0;
   for (int x = 0; x < datalen; x++) {
       k[c] = (k[c] + k[(c + 1) % keylen] + j) & 0xff;
       j = (j + k[c] + c) & 0xff;
       temp = s[c];
       s[c] = s[j];
       s[j] = temp;
       output = s[j] ^ k[c];
       data[x] = data[x] ^ output;
       c = (c + 1) & 0xff;
   } 
}

unsigned char * wrzeszcz_kdf (unsigned char *password, unsigned char *key, unsigned char *salt, int iterations, int keylen) {
    for (int x = 0; x < keylen; x++) {
        key[x] = 0;
    }
    int n = 0;
    for (int x = 0; x < strlen(password); x++) {
        key[n] = (key[n] + password[x]) % 256;
        n = (n + 1) % keylen;
    }
    int kdf_k[keylen];
    for (int x = 0; x < keylen; x++) {
        kdf_k[x] = 0;
    }
    int z[256];
    int tmp;
    int kdf_out;
    int t = 0;
    int r = 0;
    for (n = 0; n < 256; n++) {
        z[n] = n;
    }
    for (n=0; n < keylen; n++) {
        kdf_k[n % keylen] = (kdf_k[n % keylen] + key[n % keylen]) & 0xff;
        t = (t + kdf_k[n % keylen]) & 0xff; }
    for (n = 0; n < 768; n++) {
        kdf_k[n % keylen] = (kdf_k[n % keylen] + t) & 0xff;
        t = (t + kdf_k[n % keylen]) & 0xff; }
        tmp = z[n % 256];
	z[n % 256] = z[t];
	z[t] = tmp;
    int saltlen = sizeof(salt);
    for (n = 0; n < keylen; n++) {
        kdf_k[n] = (kdf_k[n] + salt[n % saltlen]) & 0xff;
        t = (t + kdf_k[n]) & 0xff; }
    for (n = 0; n < 768; n++) {
        kdf_k[n % keylen] = (kdf_k[n % keylen] + t) & 0xff;
        t = (t + kdf_k[n % keylen]) & 0xff; }
        tmp = z[n % 256];
	z[n % 256] = z[t];
	z[t] = tmp;

    n = 0;
    for (int x = 0; x < (keylen * iterations); x++) {
       kdf_k[r] = (kdf_k[r] + kdf_k[(r + 1) % keylen] + t) & 0xff;
       t = (t + kdf_k[r] + n) & 0xff;
       tmp = z[n];
       z[n] = z[t];
       z[t] = tmp;
       kdf_out = z[t] ^ kdf_k[r];
       key[r] = (unsigned char)key[r] ^ kdf_out;
       n = (n + 1) & 0xff;
       r = (r + 1) % keylen;
    }
}

unsigned char * wrzeszcz_random (unsigned char *buf, int num_bytes) {
    int keylen = 32;
    int noncelen = 16;
    unsigned char *key[keylen];
    unsigned char *nonce[noncelen];
    FILE *randfile;
    randfile = fopen("/dev/urandom", "rb");
    fread(nonce, noncelen, 1, randfile);
    fread(key, keylen, 1, randfile);
    fclose(randfile);
    wrzeszcz_crypt(buf, key, nonce, num_bytes, keylen, noncelen);
}

unsigned char *reddye_crypt(unsigned char *data, unsigned char *key, unsigned char *nonce, long datalen, int keylen, int noncelen) {
    int diff = 256 - keylen;
    int k[256] = {0};
    int j = 0;
    int i = 0;
    int c;
    int m = 256 / 2;
    int output;
    for (c=0; c < keylen; c++) {
        k[c % keylen] = (k[c % keylen] + key[c % keylen]) & 0xff;
        j = (j + k[c % keylen]) & 0xff; }
    for (c = 0; c < 256; c++) {
        k[c % keylen] = (k[c % keylen] + j) & 0xff;
        j = (j + k[c % keylen] + c) & 0xff; }
    for (c = 0; c < noncelen; c++) {
        k[c % keylen] = (k[c % keylen] + nonce[c]) & 0xff;
        j = (j + k[c % keylen]) & 0xff; }
    for (c = 0; c < 256; c++) {
        k[c % keylen] = (k[c % keylen] + j) & 0xff;
        j = (j + k[c % keylen] + c) & 0xff; }
    for (c = 0; c < diff; c++) {
        k[c+keylen] = (k[c] + k[(c + 1) % diff] + j) & 0xff;
	j = (j + k[c % diff] + c) & 0xff; }
    for (c = 0; c < 256; c++) {
        k[c] = (k[c] + k[(c + m) & 0xff] + j) & 0xff;
        j = (j + k[c] + c) & 0xff; }


   c = 0;
   for (int x = 0; x < datalen; x++) {
       k[c] = (k[c] + k[(c + 1) & 0xff] + j) & 0xff;
       j = (j + k[c] + c) & 0xff;
       output = ((j + k[c]) & 0xff) ^ k[c];
       data[x] = data[x] ^ output;
       c = (c + 1) & 0xff;
   } 
}

unsigned char * reddye_random (unsigned char *buf, int num_bytes) {
    int keylen = 32;
    int noncelen = 16;
    unsigned char *key[keylen];
    unsigned char nonce[noncelen];
    FILE *randfile;
    randfile = fopen("/dev/urandom", "rb");
    fread(&nonce, noncelen, 1, randfile);
    fread(&key, keylen, 1, randfile);
    fclose(randfile);
    reddye_crypt(buf, key, nonce, num_bytes, keylen, noncelen);
}
