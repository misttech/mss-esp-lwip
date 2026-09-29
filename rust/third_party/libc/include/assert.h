// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

#ifndef ASSERT_H
#define ASSERT_H

_Noreturn void __assert_func(const char *file, int line, const char *function,
                             const char *expression);

#ifdef NDEBUG
#define assert(e) ((void)0)
#else
#define assert(e) ((e) ? (void)0 : __assert_func(__FILE__, __LINE__, __func__, #e))
#endif

#endif /* ASSERT_H */
