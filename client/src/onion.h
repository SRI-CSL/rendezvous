#ifndef _ONION_H
#define _ONION_H

#include <stddef.h>
#include <stdio.h>
#include <time.h>
#include <inttypes.h>
#include "platform.h"

/* those onions on the menu */
enum onion_type { BASE = 0, POW, CAPTCHA, SIGNED, COLLECTION };

/* Real fields together are 2+4+4 = 10 bytes -> need at least 2 bytes of padding */
/* Fields are stored in Network Byte Order (Big Endian) */
typedef struct _onion_header {
  uint8_t	magic[6];	/* Stores magic + padding */
  uint16_t	onion_type;
  uint32_t	puzzle_size;
  uint32_t	data_size;
} PACKED onion_header_t;

typedef void* onion_t;

extern const uint8_t onion_magic[6];

/* looking at an onion qua its headers */
#define ONION_IS_ONION(X)           (memcmp(((onion_header_t *)X)->magic, onion_magic, sizeof onion_magic) == 0)
#define ONION_HEADER(X)             ((onion_header_t *)X)
#define ONION_TYPE(X)               (ntohs(((onion_header_t *) X)->onion_type))
#define ONION_PUZZLE_SIZE(X)        (ntohl(((onion_header_t *) X)->puzzle_size))
#define ONION_DATA_SIZE(X)          (ntohl(((onion_header_t *) X)->data_size))
#define ONION_SIZE(X)               (sizeof(onion_header_t) + ONION_DATA_SIZE(X) + ONION_PUZZLE_SIZE(X))

/* reaching out into the abyss */
#define ONION_PUZZLE(X)             (((char *)X) + sizeof(onion_header_t))
#define ONION_DATA(X)               (((char *)X) + sizeof(onion_header_t)  + ONION_PUZZLE_SIZE(X))



#ifdef __cplusplus
extern "C" {
#endif

  onion_t alloc_onion(int type, size_t psz, size_t dsz, void *p, void *d);

  void free_onion(onion_t o);

  void info_onion(FILE* fptr, onion_t onion);

  
  /* doesn't verify -- use verify_onion for that */
  int peel_signed_onion(onion_t onion_in, onion_t *onion_outp);
  /* note the extra argument */
  int peel_captcha_onion(char* secret, onion_t onion_in, onion_t *onion_outp);
  /* does the work */
  int peel_pow_onion(onion_t onion_in, onion_t *onion_outp);
  /* turns the collection into an argc argv pair */
  int peel_collection_onion(onion_t onion_in, int* onioncp, onion_t** onionvp);

  int read_onion(int fd, onion_t *onionp);
  
  int write_onion(int fd, onion_t onion);
  
  int file2onion(char* path, onion_t *onionp);

  int onion2file(char* path, onion_t onion);

  int verify_onion(FILE* public_key_fp, onion_t onion);

  int make_onion(int type, size_t psz, size_t dsz, void *p, void *d, onion_t *onionp);

  int make_base_onion(size_t psz, size_t dsz, void *p, void *d, onion_t *onionp);
  
  int make_pow_onion(size_t dsz, void *d, onion_t *onionp);
  int make_pow_onion_aux(char* password, size_t dsz, void *d, onion_t *onionp);
  int check_pow_onion(char* password, onion_t onion, onion_t inside);

  int makeCaptcha(const char* password, const char* path);
  int make_captcha_onion(size_t dsz, void *d, onion_t *onionp);
  int make_captcha_onion_aux(char* password, size_t dsz, void *d, onion_t *onionp);
  int check_captcha_onion(char* password, onion_t onion, onion_t inside);

  int check_signed_onion(FILE* public_key_fp, onion_t onion, onion_t inside);

  char* timestamp(time_t* nowp);


#ifdef __cplusplus
}	/*  extern "C" */

#endif  /* __cplusplus */



#endif  /* _ONION_H */
