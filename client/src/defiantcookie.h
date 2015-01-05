#ifndef _DEFIANTCOOKIE_H
#define _DEFIANTCOOKIE_H

/* Cookie Authentication between Apache module and Onion Factory */

#include "defiantbf.h"


#ifdef __cplusplus
extern "C" {
#endif

  char *construct_cookie(bf_key_pair_t *key_pair);
  char *public_key_cookie(char* cookie);
  int validate_cookie(char* cookie, bf_key_pair_t *key_pair);
  int validate_cookie_64(char* cookie, char* pk, char* did);
  
#ifdef __cplusplus
}	/*  extern "C" */

#endif /* __cplusplus */




#endif /* _DEFIANTCOOKIE_H */

