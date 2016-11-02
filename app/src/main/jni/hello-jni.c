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
#include <string.h>
#include <jni.h>
//--------------aes256--------------
#include "aes256.h"
#include "base64.h"
#ifndef LOGE
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR,"native-jni",__VA_ARGS__)
#endif

jstring getImportInfo(JNIEnv *, jstring);
jstring charToJstring(JNIEnv* envPtr, char *src);
//--------------aes256--------------

//--------------aes128--------------
#define CBC 1
#define ECB 1

#include "aes.h"
 void phex(uint8_t* str);
 void test_encrypt_ecb(uint8_t* buffer);
 void test_decrypt_ecb(void);
 void test_encrypt_ecb_verbose(void);
 void test_encrypt_cbc(void);
 void test_decrypt_cbc(void);
//--------------aes128--------------

//--------------16进制--------------
void ByteToHexStr(const unsigned char* source, char* dest, int sourceLen);
void Hex2Str( const char *sSrc,  char *sDest, int nSrcLen );
//--------------16进制--------------

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

JNIEXPORT jstring JNICALL
Java_com_example_hellojni_HelloJni_unimplementedStringFromJNI(JNIEnv *env, jobject instance,
                                                              jstring s_) {
    const char *s = (*env)->GetStringUTFChars(env, s_, 0);

    // TODO

    (*env)->ReleaseStringUTFChars(env, s_, s);

    return (*env)->NewStringUTF(env, s);
}

//把java的字符串转换成c的字符串,使用反射
char*   Jstring2CStr(JNIEnv*   env,   jstring   jstr)
{
    char*   rtn   =   NULL;
    //1:先找到字节码文件
    jclass   clsstring   =   (*env)->FindClass(env,"java/lang/String");
    jstring   strencode   =   (*env)->NewStringUTF(env,"GB2312");
    //2:通过字节码文件找到方法ID
    jmethodID   mid   =   (*env)->GetMethodID(env,clsstring,   "getBytes",   "(Ljava/lang/String;)[B");
    //3:通过方法id，调用方法
    jbyteArray   barr=   (jbyteArray)(*env)->CallObjectMethod(env,jstr,mid,strencode); // String .getByte("GB2312");
    //4:得到数据的长度
    jsize   alen   =   (*env)->GetArrayLength(env,barr);
    //5：得到数据的首地址
    jbyte*   ba   =   (*env)->GetByteArrayElements(env,barr,JNI_FALSE);
    //6:得到C语言的字符串
    if(alen   >   0)
    {
        rtn   =   (char*)malloc(alen+1);         //"\0"
        memcpy(rtn,ba,alen);
        rtn[alen]=0;
    }
    (*env)->ReleaseByteArrayElements(env,barr,ba,0);  //
    return rtn;
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
jstring getImportInfo(JNIEnv* env, jstring mingwen) {

    //0123456789ABCDEFGHIJKLMNOPQRSTUV
    unsigned char key[32] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                              0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
                              0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54,
                              0x55, 0x56 }; //密钥

//    //0123456789ABCDEF
//    unsigned char key[16] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
//                              0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46}; //密钥
    //****************************************开始加密******************************************************
    //1.初始化数据
    //初始化向量
    uint8_t iv[16] = { 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                       0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30 };

    //初始化加密参数
    aes256_context ctx;
    aes256_init(&ctx, key);

    //2.将jstring转为char
    const char *mwChar = (*env)->GetStringUTFChars(env, mingwen, JNI_FALSE);

    //3.分组填充加密
    int i;
    int mwSize = strlen(mwChar);
    int remainder = mwSize % 16;
    jstring entryptString;
    if (mwSize < 16) {	//小于16字节，填充16字节，后面填充几个几 比方说10个字节 就要补齐6个6 11个字节就补齐5个5
        uint8_t input[16];
        for (i = 0; i < 16; i++) {
            if (i < mwSize) {
                input[i] = mwChar[i];
            } else {
                input[i] = 16 - mwSize;
            }
        }
        //加密
        uint8_t output[16];
        aes256_encrypt_cbc(&ctx, input, iv, output);
        //base64加密后然后jstring格式输出
        char *enc = base64_encode(output, sizeof(output));
        entryptString = charToJstring(env, enc);

        free(enc);
    } else {	//如果是16的倍数，填充16字节，后面填充0x10
        int group = mwSize / 16;
        int size = 16 * (group + 1);
        uint8_t input[size];
        for (i = 0; i < size; i++) {
            if (i < mwSize) {
                input[i] = mwChar[i];
            } else {
                if (remainder == 0) {
                    input[i] = 0x10;
                } else {	//如果不足16位 少多少位就补几个几  如：少4为就补4个4 以此类推
                    int dif = size - mwSize;
                    input[i] = dif;
                }
            }
        }
        //加密
        uint8_t output[size];
        aes256_encrypt_cbc(&ctx, input, iv, output);
        //base64加密后然后jstring格式输出
        char *enc = base64_encode(output, sizeof(output));
        entryptString = charToJstring(env, enc);

        free(enc);
    }

    //释放mwChar
    (*env)->ReleaseStringUTFChars(env, mingwen, mwChar);

    return entryptString;

///////////////////////////*********************************************************************************
//	//0123456789ABCDEF
//	unsigned char input[64] = {
//			0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
//			0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
//			0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
//			0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
//			0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
//			0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
//			0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
//			0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10
//	}; //明文
//
//
//	//初始化向量
//	uint8_t iv[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
//
//	int i;
//	aes256_context ctx;
//	uint8_t enc_out[64];
//	aes256_init(&ctx, key);
//
//	aes256_encrypt_cbc(&ctx, input, iv, enc_out);
//	for(i = 0;i < 64;i++) {
//		LOGE("================%i", enc_out[i]);
//	}
///////////////////////////**********************************************************************************

//	return packageName;
//	if (hashCode == -1739821499) {
//		return retval;
//	} else {
//		return env->NewStringUTF(env, "error");
//	}
}

jstring charToJstring(JNIEnv* envPtr, char *src) {
    JNIEnv env = *envPtr;

    jsize len = strlen(src);
    jclass clsstring = env->FindClass(envPtr, "java/lang/String");
    jstring strencode = env->NewStringUTF(envPtr, "UTF-8");
    jmethodID mid = env->GetMethodID(envPtr, clsstring, "<init>",
                                     "([BLjava/lang/String;)V");
    jbyteArray barr = env->NewByteArray(envPtr, len);
    env->SetByteArrayRegion(envPtr, barr, 0, len, (jbyte*) src);

    return (jstring) env->NewObject(envPtr, clsstring, mid, barr, strencode);
}
void test(void);
JNIEXPORT jstring JNICALL
Java_com_example_hellojni_HelloJni_getAES(JNIEnv *env, jobject instance, jstring str_) {
//    uint8_t out[32];
//    test_encrypt_ecb(out);
    test_encrypt_ecb_verbose();
    test();
    return getImportInfo(env,str_);
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
// prints string as hex
 void phex(uint8_t* str)
{
    unsigned char i;
    for(i = 0; i < 16; ++i)
    {
        LOGE("%.2x", str[i]);
    }
    LOGE("\n");
}

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
    for(int i = 0; i < 4; ++i)
    {
        AES128_ECB_encrypt(plain_text + (i*16), key, buf+(i*16));
        LOGE(buf + (i*16));
    }
    LOGE("加密之后的base64结果:");
    char *result=base64_encode(buf,64);
    LOGE(result);
    uint8_t desResult[size];
    for (int k = 0; k < 4; ++k) {
        
    }
    AES128_ECB_decrypt(buf,key,desResult);
    
    LOGE("\n");
}


//这里进行了解密跟加密的测试
void test_encrypt_ecb(uint8_t buffer[])
{
    uint8_t key[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f'};
    uint8_t in[]  = {'h', 'e', 'l', 'l', 'o', 'w', 'r', 'l', 'd', ',', '1', '2', '3', '4', '5', '6'};
//    uint8_t out[] = {0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97};
//    uint8_t buffer[16];
    int length=32;
    LOGE("输入: ");
    LOGE(in);
    LOGE("输入,转码:");
    LOGE(base64_encode(in, length));

    //------------开始加密
    AES128_ECB_encrypt(in, key, buffer);

    LOGE("加密结果:");
    LOGE(base64_encode(buffer, length));

    //------------开始解密
    uint8_t desOut[16];
    AES128_ECB_decrypt(buffer,key,desOut);
    LOGE("解密结果:");
    LOGE(base64_encode(desOut, length));
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
    uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t in[]  = {0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97};
    uint8_t out[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    uint8_t buffer[16];

    AES128_ECB_decrypt(in, key, buffer);

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

//-------------------------------------16进制转换---------------------------------
//字节流转换为十六进制字符串
void ByteToHexStr(const unsigned char* source, char* dest, int sourceLen)
{
    short i;
    unsigned char highByte, lowByte;

    for (i = 0; i < sourceLen; i++)
    {
        highByte = source[i] >> 4;
        lowByte = source[i] & 0x0f ;

        highByte += 0x30;

        if (highByte > 0x39)
            dest[i * 2] = highByte + 0x07;
        else
            dest[i * 2] = highByte;

        lowByte += 0x30;
        if (lowByte > 0x39)
            dest[i * 2 + 1] = lowByte + 0x07;
        else
            dest[i * 2 + 1] = lowByte;
    }
    return ;
}

//字节流转换为十六进制字符串的另一种实现方式
void Hex2Str( const char *sSrc,  char *sDest, int nSrcLen )
{
    int  i;
    char szTmp[3];

    for( i = 0; i < nSrcLen; i++ )
    {
        sprintf( szTmp, "%02X", (unsigned char) sSrc[i] );
        memcpy( &sDest[i * 2], szTmp, 2 );
    }
    return ;
}
