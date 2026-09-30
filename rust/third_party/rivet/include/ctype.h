// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

/* Character classification in the "C" locale, from src/lib/libc. Each takes an
 * unsigned char value or EOF; the predicates return 1 or 0. */

#ifndef CTYPE_H
#define CTYPE_H

int isdigit(int c);
int isxdigit(int c);
int islower(int c);
int isupper(int c);
int isspace(int c);
int tolower(int c);
int toupper(int c);

#endif /* CTYPE_H */
