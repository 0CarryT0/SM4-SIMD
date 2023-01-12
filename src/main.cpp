#include <stdio.h>

#include "SM4_SIMD.h"

int main() {
    // 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
    ui32 key[4] = { 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210 };
    // 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
    ui32 in[4] = { 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210 };
    ui32 out[4];
    SM4_Enc(in, out, key, 1);
    // 68 1e df 34 d2 06 96 5e 86 b3 e9 4f 53 6e 42 46
    for (int i = 0; i < 4; i++) {
        printf("%08x", out[i]);
    }
    for (int i = 0; i < 4; i++) {
        in[i] = 0;
    }
    printf("\n");
    SM4_Dec(in, out, key, 1);
    // 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
    for (int i = 0; i < 4; i++) {
        printf("%08x", in[i]);
    }
    printf("\n");
    return 0;
}