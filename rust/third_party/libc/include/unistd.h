// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

/* The two calls this C library makes into the firmware, as newlib does into a
 * board support package. The firmware implements both. */

#ifndef UNISTD_H
#define UNISTD_H

#include <stddef.h>

typedef long ssize_t;

#define STDOUT_FILENO 1
#define STDERR_FILENO 2

/* Writes count bytes to a console; returns the number written. */
ssize_t write(int fd, const void *buf, size_t count);

/* Ends the program. It never returns. */
_Noreturn void _exit(int status);

#endif /* UNISTD_H */
