#ifndef _ONIONLIB_H
#define _ONIONLIB_H

#include <stddef.h>
#include <stdio.h>
#include <time.h>

#include <mysql.h>
#include <limits.h>
#define SIZE_T_DIGITS ((CHAR_BIT * sizeof(size_t) + 2) / 3)

#include "onion.h"

int make_signed_onion(FILE* private_key_fp, size_t dsz, void *d, onion_t *onionp);

int pack_nep(FILE* private_key_fp, FILE* public_key_fp, MYSQL *mysql, long int *onion_ids, char* nep, onion_t* signedp, FILE* logfp, int debug);

int pack_neps(FILE* private_key_fp, FILE* public_key_fp, MYSQL *mysql, long int *onion_ids,  int nepc, char** nepv, onion_t* signedp, FILE* logfp, int debug);



#endif  /* _ONIONLIB_H */
