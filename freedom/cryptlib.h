#ifndef _CRYPTLIB_H
#define _CRYPTLIB_H
#include "freedom.h"
#include <openssl/evp.h>
#include "defiantclient.h"

#ifdef __cplusplus
extern "C" {
#endif

  
  char *apr_enbase64(request_rec *r, const uchar *input, int length, int *outlen);
  uchar *apr_debase64(request_rec *r, const char *input, int *outlen);

#ifdef __cplusplus
}	/*  extern "C" */

#endif /* __cplusplus */


#endif
