// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

/* The string functions of rivet, a freestanding C library, src/lib/libc. */

#ifndef STRING_H
#define STRING_H

#include <stddef.h>

void *memcpy(void *restrict dst, const void *restrict src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t n);
char *strcpy(char *restrict dst, const char *restrict src);
char *strncpy(char *restrict dst, const char *restrict src, size_t n);
char *strcat(char *restrict dst, const char *restrict src);
char *strchr(const char *s, int c);
char *strstr(const char *haystack, const char *needle);

#endif /* STRING_H */
