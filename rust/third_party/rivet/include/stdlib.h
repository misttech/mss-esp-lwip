// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

#ifndef STDLIB_H
#define STDLIB_H

#include <stddef.h>

/* Writes "abort()" to standard error and ends the program with _exit(134). */
_Noreturn void abort(void);

/* The initial decimal number in s, as (int)strtol(s, NULL, 10). */
int atoi(const char *s);

/* Not implemented by this library: the firmware's allocator provides free. */
void free(void *ptr);

#endif /* STDLIB_H */
