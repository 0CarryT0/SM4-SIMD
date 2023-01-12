#pragma once
#define DEBUG 1
#if DEBUG
#include <stdio.h>
#endif // DEBUG

#include <cstdint>
#include <malloc.h>
typedef unsigned int ui32;
typedef unsigned char ui8;

/**
* @brief 密钥扩展
* @param MK 32位一组4组密钥
* @param rk 输出32位32组轮密钥
*/
void SM4_Key_Gen(ui32* MK, ui32* rk);

/*
* @brief SM4加密
* @param plaintext 明文
* @param ciphertext 密文
* @param key 密钥
* * @param mod 是否SIMD加速 1:加速模式 2：不加速
*/
void SM4_Enc(ui32* plaintext, ui32* ciphertext, ui32* key, ui8 mod);

/*
* @brief SM4解密
* @param plaintext 明文
* @param ciphertext 密文
* @param key 密钥
* @param mod 是否SIMD加速 0:加速模式 1：不加速
*/
void SM4_Dec(ui32* plaintext, ui32* ciphertext, ui32* key, ui8 mod);
