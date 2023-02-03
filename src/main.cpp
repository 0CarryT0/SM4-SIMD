#include <stdio.h>
#include <stdlib.h>
#include "SM4_SIMD.h"
#include <ctime>
#define INF 100000
//八组并行计算
int main() {
    ui32 key[32] = { 
        0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210,
        0x01234567, 0x89abcdef, 0xfedcba98, 0x76543211,
        0x01234567, 0x89abcdef, 0xfedcba98, 0x76543212,
        0x01234567, 0x89abcdef, 0xfedcba98, 0x76543215,
        0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210,
        0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210,
        0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210,
        0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210
    };
    ui32 in[32] = { 
        0x01234567, 0x89abcdef, 0xfedcba98, 0x76543212,
        0x01234567, 0x89abcdef, 0xfedcba98, 0x76543213,
        0x01234567, 0x89abcdef, 0xfedcba98, 0x76543215,
        0x01234567, 0x89abcdef, 0xfedcba98, 0x76543211,
        0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210,
        0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210,
        0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210,
        0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210
    };
    ui32 out1[32];
    ui32 out2[32];

    printf("正常SM4加密：\n");
    clock_t t1 = clock();
    for (int i = 0; i < INF; ++i)
        SM4_Enc(in, out1, key, 1);
    clock_t t2 = clock();
    double ts = ((double)t2 - (double)t1);
    printf("common cost = %f ms\n", ts);
    for (int i = 0; i < 32; i++) {
        printf("%08x", out1[i]);
        if (i % 4 == 3)
            printf("\n");
    }
    printf("\n");

    printf("SIMD并行加速SM4加密：\n");
    t1 = clock();
    for (int i = 0; i < INF; ++i)
        SM4_Enc(in, out2, key, 0);
    t2 = clock();
    ts = ((double)t2 - (double)t1);
    printf("SIMD cost = %f ms\n", ts);
    for (int i = 0; i < 32; i++) {
        printf("%08x", out2[i]);
        if (i % 4 == 3)
            printf("\n");
    }
    printf("\n");

    for (int i = 0; i < 32; i++) {
        in[i] = 0;
    }

    printf("正常解密：\n");
    SM4_Dec(in, out1, key, 1);
    for (int i = 0; i < 32; i++) {
        printf("%08x", in[i]);
        if (i % 4 == 3)
            printf("\n");
    }
    printf("\n");

    printf("加速解密：\n");
    SM4_Dec(in, out2, key, 1);
    for (int i = 0; i < 32; i++) {
        printf("%08x", in[i]);
        if (i % 4 == 3)
            printf("\n");
    }
    printf("\n");
    system("pause");
    return 0;
}