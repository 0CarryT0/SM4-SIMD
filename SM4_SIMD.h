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
* @brief ��Կ��չ
* @param MK 32λһ��4����Կ
* @param rk ���32λ32������Կ
*/
void SM4_Key_Gen(ui32* MK, ui32* rk);

/*
* @brief SM4����
* @param plaintext ����
* @param ciphertext ����
* @param key ��Կ
* * @param mod �Ƿ�SIMD���� 1:����ģʽ 2��������
*/
void SM4_Enc(ui32* plaintext, ui32* ciphertext, ui32* key, ui8 mod);

/*
* @brief SM4����
* @param plaintext ����
* @param ciphertext ����
* @param key ��Կ
* @param mod �Ƿ�SIMD���� 0:����ģʽ 1��������
*/
void SM4_Dec(ui32* plaintext, ui32* ciphertext, ui32* key, ui8 mod);
