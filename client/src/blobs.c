#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "blobs.h"

#define BLOBV_LENGTH  8

static int isb64digit(char c);

static int isb64digit(char c){
  return isalnum(c) || (c == '+') || (c == '/');
}



static int grow_the_blobs(blobs_t* blob);

blobs_t* alloc_blobs(int minimum){
  blobs_t* retblob = (blobs_t*)calloc(1, sizeof(blobs_t));
  if(retblob == NULL){
    return NULL;
  }
  retblob->minimum = minimum;
  retblob->blobv = (char**)calloc(BLOBV_LENGTH, sizeof(char*));
  if(retblob->blobv == NULL){
    free(retblob);
    return NULL;
  }
  retblob->blobc = 0;
  retblob->capacity = BLOBV_LENGTH;
  return retblob;
}

static int add_2_blobs(blobs_t* blob, char* buffer, size_t buffer_sz, int start, int stop);
static int add_2_blobs(blobs_t* blob, char* buffer, size_t buffer_sz, int start, int stop){
  if((start >= stop) || (stop >= buffer_sz)){ 
    return -1; 
  } else {
    int length = stop - start;
    char *nb = (char *)calloc(length + 1, sizeof(char));
    if(nb == NULL){
      return -2; 
    } else {
      memcpy(nb, &buffer[start], length);
      nb[length] = '\0';
      if((blob->blobc == blob->capacity) && grow_the_blobs(blob) == 0){
        return -3;
      } else {
        blob->blobv[blob->blobc] = nb;
        blob->blobc += 1;
        return 0;
      }
    }
  }
}

static int grow_the_blobs(blobs_t* blob){
  if(blob != NULL){
    int ncapacity = 2 * blob->capacity;
     char** nblobv = (char**)calloc(ncapacity, sizeof(char*));
     if(nblobv != NULL){
      int index;
      for(index = 0; index < blob->blobc; index++){
        nblobv[index] = blob->blobv[index];
      }
      free(blob->blobv);
      blob->blobv = nblobv;
      blob->capacity = ncapacity;
      return 1;
     } 
  }
  return 0;
}

int get_blobs(char* buffer, size_t buffer_sz, blobs_t* blobs){
  int blobcount = 0;
  if(blobs != NULL){
    int index = 0, current_start = 0, minimum = blobs->minimum;
    while(index < buffer_sz){
      char c = buffer[index];
      if( c == '\0' || !isb64digit(c)){
        //check if we have a blob
        if(index - current_start > minimum){
          int retcode = add_2_blobs(blobs, buffer, buffer_sz, current_start + 1, index);
          if(retcode < 0){
            return blobcount;
          } else {
            blobcount++;
          }
        }
        current_start = index;
      }
      index++;
    }
  }
  return blobcount;
}


void free_blobs(blobs_t* blobs){
  free(blobs->blobv);
  free(blobs);
}

void print_blobs(FILE* stream, blobs_t* blobs){
  int index;
  if( blobs->blobc > 0 ){
    for(index = 0; index < blobs->blobc; index++){
      fprintf(stream, "blobv[%d] = %s\n", index, blobs->blobv[index]);
    } 
  } else {
    fprintf(stream, "empty blobs\n");
  }
}




