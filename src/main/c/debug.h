#ifndef _debug_h
#define _debug_h

#include <stdio.h>

#ifndef NDEBUG
#define debug(D, ...)
#else
#define debug(D, ...) fprintf(stderr, "DEBUG %s in '%s' line %d:  " D "\n", __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#endif

#endif