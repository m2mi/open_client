#ifndef _log_h_
#define _log_h_

#ifndef NDEBUG
#define debug(D, ...)
#else
#define debug(D, ...) fprintf(stderr, "DEBUG %s in '%s' line %d:  " D "\n", __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#endif

#define error(D, ...) fprintf(stderr, "ERROR %s in '%s' line %d:  " D "\n", __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#endif