//
// Created by Administrator on 2016/11/4.
//

#ifndef HELLO_JNI_HELLO_JNI_H
#define HELLO_JNI_HELLO_JNI_H
#ifndef LOGE
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,"native-jni",__VA_ARGS__)
#endif

#define CBC 1
#define ECB 1

#include "aes.h"

char* AES_128_ECB_PKCS5Padding_Encrypt(uint8_t *in, uint8_t *out, const uint8_t *key);
char* AES_128_ECB_PKCS5Padding_Decrypt(const char *in, char *out, const char *key);
void test(void);
void test_encrypt_ecb(uint8_t* buffer);
void test_decrypt_ecb(void);
void test_encrypt_ecb_verbose(void);
void test_encrypt_cbc(void);
void test_decrypt_cbc(void);
void test_test_encrypt_ecb_padding(void);
void LOGEX(uint8_t* src,const int length);

static char staticStr[]="abc";
//static char staticCount=1;
static char* add( const char *str);

#endif //HELLO_JNI_HELLO_JNI_H
