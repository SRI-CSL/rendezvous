#ifndef _DEFIANTUTILS_H
#define _DEFIANTUTILS_H
#include <stdlib.h>

char* duplicate(const char* value);

typedef struct _response {
  char*  buffer;
  size_t buffer_size;
} response;

size_t callback(void *contents, size_t size, size_t nmemb, void *userp);

#endif /* _DEFIANTUTILS_H */
