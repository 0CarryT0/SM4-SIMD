#include "SM4_SIMD.h"

//32位value循环左移shift
#define rotl(value, shift) ((value << shift)|(value >> (32 - shift)))
//一种转置，手推看看。
#define MM256_PACK0_EPI32(a, b, c, d)                  \
    _mm256_unpacklo_epi64(_mm256_unpacklo_epi32(a, b), \
                          _mm256_unpacklo_epi32(c, d))
#define MM256_PACK1_EPI32(a, b, c, d)                  \
    _mm256_unpackhi_epi64(_mm256_unpacklo_epi32(a, b), \
                          _mm256_unpacklo_epi32(c, d))
#define MM256_PACK2_EPI32(a, b, c, d)                  \
    _mm256_unpacklo_epi64(_mm256_unpackhi_epi32(a, b), \
                          _mm256_unpackhi_epi32(c, d))
#define MM256_PACK3_EPI32(a, b, c, d)                  \
    _mm256_unpackhi_epi64(_mm256_unpackhi_epi32(a, b), \
                          _mm256_unpackhi_epi32(c, d))

void _SM4_do(ui32* input, ui32* output, ui32* rk, ui8 mod);
void _SM4_SIMD_do8(ui32* input, ui32* output, __m256i* rk, ui8 mod);

void SM4_Key_Gen(ui32* MK, ui32* rk){
    ui32 K[36];
    ui32 tmp;
    ui8* tmp_8ptr = (ui8*)&tmp;
    for (int i = 0; i < 4; ++i){
        K[i] = MK[i] ^ FK[i];
    }
    for (int i = 0; i < 32; ++i) {
        tmp = K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i];
        K[i + 4] = K[i] ^ STR0[tmp_8ptr[0]] ^ STR1[tmp_8ptr[1]] ^ STR2[tmp_8ptr[2]] ^ STR3[tmp_8ptr[3]];
        rk[i] = K[i + 4];
    }
}

void SM4_Key_Gen_SIMD(ui32* MK, __m256i* rk){
    __m256i tmp[4], K[36], mask;
    mask = _mm256_set1_epi32(0xFF);
    //装载
    tmp[0] = _mm256_loadu_si256((const __m256i*)MK + 0);
    tmp[1] = _mm256_loadu_si256((const __m256i*)MK + 1);
    tmp[2] = _mm256_loadu_si256((const __m256i*)MK + 2);
    tmp[3] = _mm256_loadu_si256((const __m256i*)MK + 3);
    //转置
    K[0] = MM256_PACK0_EPI32(tmp[0], tmp[1], tmp[2], tmp[3]);
    K[1] = MM256_PACK1_EPI32(tmp[0], tmp[1], tmp[2], tmp[3]);
    K[2] = MM256_PACK2_EPI32(tmp[0], tmp[1], tmp[2], tmp[3]);
    K[3] = MM256_PACK3_EPI32(tmp[0], tmp[1], tmp[2], tmp[3]);
    //xor FK
    K[0] = _mm256_xor_si256(K[0], _mm256_set1_epi32(FK[0]));
    K[1] = _mm256_xor_si256(K[1], _mm256_set1_epi32(FK[1]));
    K[2] = _mm256_xor_si256(K[2], _mm256_set1_epi32(FK[2]));
    K[3] = _mm256_xor_si256(K[3], _mm256_set1_epi32(FK[3]));

    for (int i = 0; i < 32; ++i) {
        tmp[0] = _mm256_xor_si256(
            _mm256_xor_si256(K[i + 1], K[i + 2]),
            _mm256_xor_si256(K[i + 3], _mm256_set1_epi32(CK[i])));

        tmp[1] = _mm256_xor_si256(
            K[i], _mm256_i32gather_epi32((const int*)STR0,
                _mm256_and_si256(tmp[0], mask), 4));
        tmp[0] = _mm256_srli_epi32(tmp[0], 8);
        tmp[1] = _mm256_xor_si256(
            tmp[1], _mm256_i32gather_epi32(
                (const int*)STR1, _mm256_and_si256(tmp[0], mask), 4));
        tmp[0] = _mm256_srli_epi32(tmp[0], 8);
        tmp[1] = _mm256_xor_si256(
            tmp[1], _mm256_i32gather_epi32(
                (const int*)STR2, _mm256_and_si256(tmp[0], mask), 4));
        tmp[0] = _mm256_srli_epi32(tmp[0], 8);
        tmp[1] = _mm256_xor_si256(
            tmp[1], _mm256_i32gather_epi32(
                (const int*)STR3, _mm256_and_si256(tmp[0], mask), 4));

        K[i + 4] = tmp[1];
        rk[i] = K[i + 4];
    }
}

void SM4_Enc(ui32* plaintext, ui32* ciphertext, ui32* key, ui8 mod) {
    if (mod == 1) {
        ui32* rk = (ui32*)malloc(32 * sizeof(ui32));
        for (int i = 0; i < 8; ++i) {
            SM4_Key_Gen(key + (i * 4), rk);
            _SM4_do(plaintext + (i * 4), ciphertext + (i * 4), rk, 0);
        }
        free(rk);
    }
    else {
        __m256i* rk = (__m256i*)malloc(32 * sizeof(__m256i));
        //8组轮密钥并行生成
        SM4_Key_Gen_SIMD(key, rk);
        _SM4_SIMD_do8(plaintext, ciphertext, rk, 0);
        free(rk);
    }
}

void SM4_Dec(ui32* plaintext, ui32* ciphertext, ui32* key, ui8 mod) {
    if (mod == 1) {
        ui32* rk = (ui32*)malloc(32 * sizeof(ui32));
        for (int i = 0; i < 8; ++i) {
            SM4_Key_Gen(key + (i * 4), rk);
            _SM4_do(ciphertext + (i * 4), plaintext + (i * 4), rk, 1);
        }
        free(rk);
    }
    else {
        __m256i* rk = (__m256i*)malloc(32 * sizeof(__m256i));
        //8组轮密钥需要全部先生成
        SM4_Key_Gen_SIMD(key, rk);
        _SM4_SIMD_do8(ciphertext, plaintext, rk, 1);
        free(rk);
    }
}

void _SM4_do(ui32* input, ui32* output, ui32* rk, ui8 mod) {
    ui32 P[36];
    for (int i = 0; i < 4; ++i)
        P[i] = input[i];
    ui32 tmp, res;
    ui8* tmp_8ptr = (ui8*)&tmp;
    for (int i = 0; i < 32; ++i) {
        ui32 RKi = (mod == 0) ? rk[i] : rk[31 - i];
        tmp = RKi ^ P[i + 1] ^ P[i + 2] ^ P[i + 3];
        res = P[i] ^ ST0[tmp_8ptr[0]] ^ ST1[tmp_8ptr[1]] 
            ^ ST2[tmp_8ptr[2]] ^ ST3[tmp_8ptr[3]];
        P[i + 4] = res;
    }
    for (int i = 0; i < 4; ++i) {
        output[i] = P[35 - i];
    }
}

void _SM4_SIMD_do8(ui32* input, ui32* output, __m256i* rk, ui8 mod) {
    __m256i P[36], tmp[4], mask;
    mask = _mm256_set1_epi32(0xFF);
    //加载数据
    tmp[0] = _mm256_loadu_si256((const __m256i*)input + 0);
    tmp[1] = _mm256_loadu_si256((const __m256i*)input + 1);
    tmp[2] = _mm256_loadu_si256((const __m256i*)input + 2);
    tmp[3] = _mm256_loadu_si256((const __m256i*)input + 3);
    //转置存储，方便并行
    P[0] = MM256_PACK0_EPI32(tmp[0], tmp[1], tmp[2], tmp[3]);
    P[1] = MM256_PACK1_EPI32(tmp[0], tmp[1], tmp[2], tmp[3]);
    P[2] = MM256_PACK2_EPI32(tmp[0], tmp[1], tmp[2], tmp[3]);
    P[3] = MM256_PACK3_EPI32(tmp[0], tmp[1], tmp[2], tmp[3]);
    // 32轮迭代
    for (int i = 0; i < 32; i++) {
        __m256i k;
        if (mod == 0)
            k = rk[i];
        else
            k = rk[31 - i];

        tmp[0] = _mm256_xor_si256(_mm256_xor_si256(P[i + 1], P[i + 2]),
            _mm256_xor_si256(P[i + 3], k));
        //查表
        tmp[1] = _mm256_xor_si256(
            P[i], _mm256_i32gather_epi32((const int*)ST0,
                _mm256_and_si256(tmp[0], mask), 4));
        tmp[0] = _mm256_srli_epi32(tmp[0], 8);
        tmp[1] = _mm256_xor_si256(
            tmp[1], _mm256_i32gather_epi32(
                (const int*)ST1, _mm256_and_si256(tmp[0], mask), 4));
        tmp[0] = _mm256_srli_epi32(tmp[0], 8);
        tmp[1] = _mm256_xor_si256(
            tmp[1], _mm256_i32gather_epi32(
                (const int*)ST2, _mm256_and_si256(tmp[0], mask), 4));
        tmp[0] = _mm256_srli_epi32(tmp[0], 8);
        tmp[1] = _mm256_xor_si256(
            tmp[1], _mm256_i32gather_epi32(
                (const int*)ST3, _mm256_and_si256(tmp[0], mask), 4));

        P[i + 4] = tmp[1];
    }
    //恢复分组并装填
    _mm256_storeu_si256((__m256i*)output + 0,
        MM256_PACK0_EPI32(P[35], P[34], P[33], P[32]));
    _mm256_storeu_si256((__m256i*)output + 1,
        MM256_PACK1_EPI32(P[35], P[34], P[33], P[32]));
    _mm256_storeu_si256((__m256i*)output + 2,
        MM256_PACK2_EPI32(P[35], P[34], P[33], P[32]));
    _mm256_storeu_si256((__m256i*)output + 3,
        MM256_PACK3_EPI32(P[35], P[34], P[33], P[32]));
}