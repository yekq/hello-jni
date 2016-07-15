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
