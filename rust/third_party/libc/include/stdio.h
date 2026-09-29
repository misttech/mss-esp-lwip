// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

#ifndef STDIO_H
#define STDIO_H

#include <stdarg.h>
#include <stddef.h>

/* Writes one byte to standard output through write(). */
int putchar(int c);

/* Not implemented by this library: stable Rust cannot define a C variadic
 * function, so the firmware provides printf, formatting with its own vsnprintf
 * and writing through write(). */
int printf(const char *format, ...) __attribute__((format(printf, 1, 2)));

#endif /* STDIO_H */
