#ifndef _JPEG_STEG_H
#define _JPEG_STEG_H

#include  "onion.h"

#ifdef __cplusplus
extern "C" {
#endif
  
  /* note that onion is an encrypted onion (i.e. not an onion as far as headers go :-) */

  int embed(const char* secret, const char* onion, size_t onion_sz, const char* image_path, char** image_bytesp, size_t* image_szp);

  int extract(const char* secret, const char* image_bytes, size_t image_sz,  char** onionp, size_t* onion_szp);

  int extract_n_save(const char* secret, const char* image_bytes, size_t image_sz,  char** onionp, size_t* onion_szp, char** image_path, char** image_dir);

  char* random_file(const char* directory);


#ifdef __cplusplus
}	/*  extern "C" */

#endif /* __cplusplus */




#endif /* _JPEG_STEG_H */

