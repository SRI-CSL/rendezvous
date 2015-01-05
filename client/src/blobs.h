#ifndef _BLOBS_H
#define _BLOBS_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

  /*
   *
   *  A little library for extracting blobs from cookies, urls etc.
   *  Mod freedom is going to use this, amongst others. In the 
   *  forthcoming "mod_freedom v 2.0"
   *
   */


  typedef struct blobs {
    int capacity;            /* number of blobs able to be stored in blobv   */
    int blobc;               /* number of blobs stored in blobsv             */
    char** blobv;            /* da blobs                                     */
    int minimum;             /* minumum size required                        */
  } blobs_t;


  blobs_t* alloc_blobs(int minimum);

  int get_blobs(char* buffer, size_t buffer_sz, blobs_t* blobs);
  
  void free_blobs(blobs_t* blobs);

  void print_blobs(FILE* stream, blobs_t* blobs);

  

#ifdef __cplusplus
}	/*  extern "C" */

#endif  /* __cplusplus */



#endif  /* _BLOBS_H */
