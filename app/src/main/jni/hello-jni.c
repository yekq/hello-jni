/*
 * Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "hello-jni.h"

/* This is a trivial JNI example where we use a native method
 * to return a new VM String. See the corresponding Java source
 * file located at:
 *
 *   apps/samples/hello-jni/project/src/com/example/hellojni/HelloJni.java
 */
jstring
Java_com_example_hellojni_HelloJni_stringFromJNI( JNIEnv* env,
                                                  jobject thiz )
{
#if defined(__arm__)
  #if defined(__ARM_ARCH_7A__)
    #if defined(__ARM_NEON__)
      #if defined(__ARM_PCS_VFP)
        #define ABI "armeabi-v7a/NEON (hard-float)"
      #else
        #define ABI "armeabi-v7a/NEON"
      #endif
    #else
      #if defined(__ARM_PCS_VFP)
        #define ABI "armeabi-v7a (hard-float)"
      #else
        #define ABI "armeabi-v7a"
      #endif
    #endif
  #else
   #define ABI "armeabi"
  #endif
#elif defined(__i386__)
   #define ABI "x86"
#elif defined(__x86_64__)
   #define ABI "x86_64"
#elif defined(__mips64)  /* mips64el-* toolchain defines __mips__ too */
   #define ABI "mips64"
#elif defined(__mips__)
   #define ABI "mips"
#elif defined(__aarch64__)
   #define ABI "arm64-v8a"
#else
   #define ABI "unknown"
#endif

    return (*env)->NewStringUTF(env, "Kenny:Hello from JNI !  Compiled with ABI " ABI ".");
}

/*
 * Class:     com_demo_passwd_MainActivity
 * Method:    encodeFromC
 * Signature: (Ljava/lang/String;I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_example_hellojni_HelloJni_encodeFromC
        (JNIEnv *env, jobject obj, jstring passwd, jint length)
{
    //1:将java的字符串转化为c语言
//    char* cstr = Jstring2CStr(env, passwd);
    char *cstr = (*env)->GetStringUTFChars(env, passwd, 0);
    int i = 0;
    //2:给C语言字符加1
    for(i = 0; i < length; i++)
    {
        *(cstr + i) += 1;
    }
    //3:将c语言字符串转化为java字符串
    return (*env)->NewStringUTF(env, cstr);
}

/*
 * Class:     com_demo_passwd_MainActivity
 * Method:    decodeFromC
 * Signature: (Ljava/lang/String;I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_example_hellojni_HelloJni_decodeFromC
        (JNIEnv *env, jobject obj, jstring passwd, jint length)
{
    //1:将java的字符串转化为c语言
//    char* cstr = Jstring2CStr(env, passwd);
    char *cstr = (*env)->GetStringUTFChars(env, passwd, 0);
    int i = 0;
    //2:给C语言字符减1
    for(i = 0; i < length; i++)
    {
        *(cstr + i) -= 1;
    }
    //3:将c语言字符串转化为java字符串
    return (*env)->NewStringUTF(env, cstr);
}

JNIEXPORT jstring JNICALL
Java_com_example_hellojni_HelloJni_getAES(JNIEnv *env, jobject instance, jstring str_) {
//    uint8_t out[16];
//    memset(out,0,16);
//    test_encrypt_ecb(out);

//    test_encrypt_ecb_verbose();
//    char * a="hellowrld,123456";
//    char *base64en=base64_encode(a,strlen(a));
//    LOGE(base64en);
//    test_decrypt_ecb();

//    unsigned char a1=HEX[0];
//    unsigned char a2=HEX[1];
//    unsigned char a14=HEX[14];
//    unsigned char a15=HEX[15];
    const uint8_t *in= (const uint8_t *) (*env)->GetStringUTFChars(env, str_, JNI_FALSE);
//    uint8_t in[]="1234567890abcdef12";
    const uint8_t key[]="1234567890abcdef";
    uint8_t *out2=NULL;
    char *baseResult= AES_128_ECB_PKCS5Padding_Encrypt(in, out2, key);
    (*env)->ReleaseStringUTFChars(env, str_, in);
    return (*env)->NewStringUTF(env,baseResult);
}

void test(void)
{
    char str[]="abcd";
    char copy[4];
    for (int i = 0; i < 4; i++) {
        copy[i]=str[i];
    }
    LOGE(str);
    LOGE("复制:");
    LOGE(copy);
}

//-------------------------------------AES128-------------------------------------

void test_encrypt_ecb_verbose(void)
{
    // Example of more verbose verification

    uint8_t  buf[64], buf2[64];

//    // 128bit key
//    uint8_t key[16] =        { (uint8_t) 0x2b, (uint8_t) 0x7e, (uint8_t) 0x15, (uint8_t) 0x16, (uint8_t) 0x28, (uint8_t) 0xae, (uint8_t) 0xd2, (uint8_t) 0xa6, (uint8_t) 0xab, (uint8_t) 0xf7, (uint8_t) 0x15, (uint8_t) 0x88, (uint8_t) 0x09, (uint8_t) 0xcf, (uint8_t) 0x4f, (uint8_t) 0x3c };

    // 512bit text
//    uint8_t plain_text[64] = { (uint8_t) 'a', (uint8_t) 'z', (uint8_t) 0x44, (uint8_t) 0x45, (uint8_t) 0x2e, (uint8_t) 0x40, (uint8_t) 0x9f, (uint8_t) 0x96, (uint8_t) 0xe9, (uint8_t) 0x3d, (uint8_t) 0x7e, (uint8_t) 0x11, (uint8_t) 0x73, (uint8_t) 0x93, (uint8_t) 0x17, (uint8_t) 0x2a,
//                               (uint8_t) 0xae, (uint8_t) 0x2d, (uint8_t) 0x8a, (uint8_t) 0x57, (uint8_t) 0x1e, (uint8_t) 0x03, (uint8_t) 0xac, (uint8_t) 0x9c, (uint8_t) 0x9e, (uint8_t) 0xb7, (uint8_t) 0x6f, (uint8_t) 0xac, (uint8_t) 0x45, (uint8_t) 0xaf, (uint8_t) 0x8e, (uint8_t) 0x51,
//                               (uint8_t) 0x30, (uint8_t) 0xc8, (uint8_t) 0x1c, (uint8_t) 0x46, (uint8_t) 0xa3, (uint8_t) 0x5c, (uint8_t) 0xe4, (uint8_t) 0x11, (uint8_t) 0xe5, (uint8_t) 0xfb, (uint8_t) 0xc1, (uint8_t) 0x19, (uint8_t) 0x1a, (uint8_t) 0x0a, (uint8_t) 0x52, (uint8_t) 0xef,
//                               (uint8_t) 0xf6, (uint8_t) 0x9f, (uint8_t) 0x24, (uint8_t) 0x45, (uint8_t) 0xdf, (uint8_t) 0x4f, (uint8_t) 0x9b, (uint8_t) 0x17, (uint8_t) 0xad, (uint8_t) 0x2b, (uint8_t) 0x41, (uint8_t) 0x7b, (uint8_t) 0xe6, (uint8_t) 0x6c, (uint8_t) 0x37, (uint8_t) 0x10 };
    const int size=64;
    // 512bit text
//    uint8_t plain_text[size];
    uint8_t plain_text[size]="abcdefgh12345678abcdefgh87654321abcdefgh";
//    for (int i = 0; i < size; ++i) {
//        plain_text[i]=(uint8_t)input[i];
//    }
    // 128bit key

    uint8_t key[]="qwertyuioasdfghj";

    memset(buf, 0, size);
    memset(buf2, 0, size);

    // print text to encrypt, key and IV
    LOGE("ECB encrypt verbose:\n\n");
    LOGE("plain text:\n");
    LOGE(plain_text);
    LOGE("\n");

    LOGE("key:\n");
    LOGE(key);
    LOGE("\n");

    // print the resulting cipher as 4 x 16 byte strings
    LOGE("ciphertext:\n");
    for(int i = 0; i < 4; i++)
    {
        AES128_ECB_encrypt(plain_text + (i*16), key, buf+(i*16));
    }
    LOGE("加密之后的base64结果:");
    char *result=base64_encode(unsignedCharToChar(buf,64),64);
    LOGE(result);
    uint8_t desResult[size];
    for (int k = 0; k < 4; ++k) {

    }
    AES128_ECB_decrypt(buf,key,desResult);

    LOGE("\n");
}

/**
 * 打印 unsigned的char
 */
void LOGEX(uint8_t* str, const int length)
{
    char* copy=unsignedCharToChar(str,length);
    copy[length]='\0';
    LOGE(copy);
}


//这里进行了解密跟加密的测试
void test_encrypt_ecb(uint8_t buffer[])
{
//    uint8_t key[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f'};
    uint8_t key[]="1234567890abcdef";
//    uint8_t in[16]  = {'1', 0x0f, 0x0f, 0x0f,0x0f, 0x0f, 0x0f,0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f};
//    uint8_t in[]="hellowrld,123456";
//    uint8_t out[] = {0x3a, 0xd7,  0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97};
//    uint8_t buffer[16];
    uint8_t in[16];
    memset(in,0x0f,16);
    in[0]='1';

    int length=16;
    LOGE("输入: ");
    LOGEX(in,16);
    LOGE("输入,转码:");
    LOGE(base64_encode(in, 16));

    //------------开始加密
    AES128_ECB_encrypt(in, key, buffer);

    LOGE("加密结果:");
    LOGE(base64_encode(buffer, 16));

    //------------开始解密
    uint8_t desOut[16];
    AES128_ECB_decrypt(buffer,key,desOut);
    LOGE("解密结果:");
//    LOGE(base64_encode(desOut, length));
    LOGEX(desOut,16);
}

/**
 * 不定长加密,pkcs5padding
 */
char* AES_128_ECB_PKCS5Padding_Encrypt(uint8_t *in, uint8_t *out, const uint8_t *key)
{

//    uint8_t key[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f'};
//    uint8_t in[16]  = {'1', 0x0f, 0x0f, 0x0f,0x0f, 0x0f, 0x0f,0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f};
//    uint8_t in[]="hellowrld,123456";
//    uint8_t out[] = {0x3a, 0xd7,  0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97};
//    uint8_t buffer[16];
//    memset(in,0x0f,16);

    int inLength= (int) strlen(in);//输入的长度
    int remainder = inLength % 16;
    LOGE("输入: ");
    LOGEX(in,inLength);
    LOGE("输入,转码:");
    LOGE(base64_encode(in, inLength));
    LOGE("key:");
    LOGEX(key,strlen(key));
    uint8_t *paddingInput;
    int paddingInputLengt=0;
    if(inLength<16)
    {
        paddingInput=(uint8_t*)malloc(16);
        paddingInputLengt=16;
        for (int i = 0; i < 16; i++) {
            if (i < inLength) {
                paddingInput[i] = in[i];
            } else {
                paddingInput[i] = HEX[16 - inLength];
            }
        }
    }else
    {
        int group = inLength / 16;
        int size = 16 * (group + 1);
        paddingInput=(uint8_t*)malloc(size);
        paddingInputLengt=size;

        int dif = size - inLength;
        for (int i = 0; i < size; i++) {
            if (i < inLength) {
                paddingInput[i] = in[i];
            } else {
                if (remainder == 0) {
                    //刚好是16倍数,就填充16个16
                    paddingInput[i] = HEX[0];
                } else {	//如果不足16位 少多少位就补几个几  如：少4为就补4个4 以此类推
                    paddingInput[i] = HEX[dif];
                }
            }
        }
    }
    int count=paddingInputLengt / 16;
    //开始分段加密
    out=(uint8_t*)malloc(paddingInputLengt);
    for (int i = 0; i < count; ++i) {
        AES128_ECB_encrypt(paddingInput+i*16, key, out+i*16);
    }
    char * base64En=base64_encode(out,paddingInputLengt);
    LOGE(base64En);
    free(paddingInput);
    free(out);
    return base64En;
}
/**
 * 不定长解密,pkcs5padding
 */
char* AES_128_ECB_PKCS5Padding_Decrypt(const char *in, char *out, const char *key)
{
    //加密前:1
    //key:1234567890abcdef
    //加密后:qkrxxA9fIF636aITDRJhcg==

    in="qkrxxA9fIF636aITDRJhcg==";
    key="1234567890abcdef";
    uint8_t *inputDesBase64= (uint8_t *) base64_decode(in, strlen(in));
    size_t inputLength=strlen(inputDesBase64);
    out=malloc(inputLength);
    //Base64转码
    size_t count=inputLength/16;
    for (size_t i = 0; i < count; ++i) {
        AES128_ECB_decrypt(inputDesBase64+i*16,key,out+i*16);
    }
    return out;
}

void test_decrypt_cbc(void)
{
    // Example "simulating" a smaller buffer...

    uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    uint8_t in[]  = { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
                      0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
                      0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
                      0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 };
    uint8_t out[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                      0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                      0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                      0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
    uint8_t buffer[64];

    AES128_CBC_decrypt_buffer(buffer+0, in+0,  16, key, iv);
    AES128_CBC_decrypt_buffer(buffer+16, in+16, 16, 0, 0);
    AES128_CBC_decrypt_buffer(buffer+32, in+32, 16, 0, 0);
    AES128_CBC_decrypt_buffer(buffer+48, in+48, 16, 0, 0);

    printf("CBC decrypt: ");

    if(0 == memcmp((char*) out, (char*) buffer, 64))
    {
        printf("SUCCESS!\n");
    }
    else
    {
        printf("FAILURE!\n");
    }
}

void test_encrypt_cbc(void)
{
    uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    uint8_t in[]  = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                      0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                      0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                      0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
    uint8_t out[] = { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
                      0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
                      0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
                      0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 };
    uint8_t buffer[64];

    AES128_CBC_encrypt_buffer(buffer, in, 64, key, iv);

    printf("CBC encrypt: ");

    if(0 == memcmp((char*) out, (char*) buffer, 64))
    {
        printf("SUCCESS!\n");
    }
    else
    {
        printf("FAILURE!\n");
    }
}


void test_decrypt_ecb(void)
{
//    uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
//    uint8_t in[]  = {0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97};
    uint8_t out[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    uint8_t buffer[16];
    uint8_t key[]="1234567890abcdef";
    uint8_t in[]="qKCRVZ8FzL4t4oPFg/h1aqASwxI=";
    AES128_ECB_decrypt(base64_decode(in,strlen(in)), key, buffer);
    LOGE(unsignedCharToChar(buffer,strlen(buffer)));
    printf("ECB decrypt: ");

    if(0 == memcmp((char*) out, (char*) buffer, 16))
    {
        printf("SUCCESS!\n");
    }
    else
    {
        printf("FAILURE!\n");
    }
}
//-------------------------------------AES128-------------------------------------

static char* add( const char *str)
{
//     char staticStr[10]="abc";
    strcat(staticStr,str);
    return staticStr;
}
JNIEXPORT jstring JNICALL
Java_com_example_hellojni_HelloJni_testStatic(JNIEnv *env, jobject instance, jstring str_) {
    const char *str = (*env)->GetStringUTFChars(env, str_, 0);


//    (*env)->ReleaseStringUTFChars(env, str_, str);
//    staticCount++;
//    staticStr[0]=staticCount;
    return (*env)->NewStringUTF(env, add(str));
}


JNIEXPORT jstring JNICALL
Java_com_example_hellojni_HelloJni_getDes(JNIEnv *env, jobject instance, jstring str_) {
/*    const char *str = (*env)->GetStringUTFChars(env, str_, 0);

    // TODO

    (*env)->ReleaseStringUTFChars(env, str_, str);

    return (*env)->NewStringUTF(env, returnValue);*/
    char * desResult=AES_128_ECB_PKCS5Padding_Decrypt(NULL,NULL,NULL);
    return (*env)->NewStringUTF(env, desResult);
}