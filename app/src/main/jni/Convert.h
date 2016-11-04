//
// Created by Administrator on 2016/11/4.
//
#ifndef HELLO_JNI_CONVERT_H
#define HELLO_JNI_CONVERT_H

#include <stddef.h>
#include <malloc.h>
#include <string.h>
#include <stdio.h>

void ByteToHexStr(const unsigned char* source, char* dest, int sourceLen);
void Hex2Str( const char *sSrc,  char *sDest, int nSrcLen );
char* unsignedCharToChar(unsigned char* unChar,const int length);
#endif //HELLO_JNI_CONVERT_H
