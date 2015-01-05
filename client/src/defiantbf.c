#include "p.h"
#include "defiantbf.h"
#include "defianterrors.h"
#include "defiantconstants.h"
#include "defiantclient.h"
#include "utils.h"

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/err.h>

/* a hack due to me resisting the urge to make all size_t vars ints */
#define INT(X) ((int)X)

int bf_write_master_key(FILE* fp, bf_master_key_t *master_key){
  if((fp == NULL) || (master_key == NULL)){
    return DEFIANT_ARGS;
  } else {
    int esz = pairing_length_in_bytes_Zr(master_key->pairing);
    uchar *ebuffer = (uchar *)calloc(esz, sizeof(uchar));
    if(ebuffer != NULL){
      size_t bytes_written = 0;
      element_to_bytes(ebuffer, master_key->s);
      bytes_written = fwrite(ebuffer, sizeof(uchar), esz, fp);
      free(ebuffer);
      return INT(bytes_written) == esz ? DEFIANT_OK : DEFIANT_EOF;
    }
    return DEFIANT_MEMORY;
  }
}

int bf_read_master_key(FILE* fp, bf_master_key_t **master_keyp){
  int retcode =  DEFIANT_ARGS;
  if((fp != NULL) && (master_keyp != NULL)){
    bf_master_key_t *master_key = (bf_master_key_t *)calloc(1, sizeof(bf_master_key_t));
    if(master_key != NULL){
      if(!pairing_init_set_str(master_key->pairing, pairing_descriptionB)){
        int esz = pairing_length_in_bytes_Zr(master_key->pairing);
        uchar *ebuffer = (uchar *)calloc(esz, sizeof(uchar));
        if(ebuffer != NULL){
          size_t bytes_read = fread(ebuffer, sizeof(uchar), esz, fp);
          if(INT(bytes_read) == esz){
            element_init_Zr(master_key->s, master_key->pairing);
            element_from_bytes(master_key->s, ebuffer);
            *master_keyp = master_key;
            retcode = DEFIANT_OK;
          } else {
            *master_keyp = NULL;
            retcode = DEFIANT_EOF;
          }
          free(ebuffer);
        } else {
          retcode = DEFIANT_MEMORY;
        }
      } else {
        free(master_key);
        master_key = NULL;
        retcode = DEFIANT_DATA;
      }
    } else {
      retcode = DEFIANT_MEMORY;
    }
  }
  return retcode;
}

int bf_write_key_pair(FILE* fp, bf_key_pair_t *key_pair){
  int retcode =  DEFIANT_ARGS;
  if((fp != NULL) && (key_pair != NULL)){
    int esz = pairing_length_in_bytes_compressed_G1(key_pair->pairing);
    uchar *ebuffer = (uchar *)calloc(esz, sizeof(uchar));
    if(ebuffer != NULL){
      size_t bytes_written = 0;
      element_to_bytes_compressed(ebuffer, key_pair->Qid);
      bytes_written = fwrite(ebuffer, sizeof(uchar), esz, fp);
      if(INT(bytes_written) == esz){
        element_to_bytes_compressed(ebuffer, key_pair->Did);
        bytes_written = fwrite(ebuffer, sizeof(uchar), esz, fp);
        if(INT(bytes_written) == esz){
          int len = strlen(key_pair->public_key);
          bytes_written = fwrite(key_pair->public_key, sizeof(char), len, fp);
          if(INT(bytes_written) == len){
            retcode = DEFIANT_OK;
          } else {
            retcode = DEFIANT_EOF;
          }
        } else {
          retcode = DEFIANT_EOF;
        }
      }  else {
        retcode = DEFIANT_EOF;
      }
      free(ebuffer);
    } else {
      retcode = DEFIANT_MEMORY;
    }
  }
  return retcode;
}


int bf_read_key_pair(FILE* fp, bf_key_pair_t **key_pairp){
  int retcode = DEFIANT_ARGS;
  bf_key_pair_t *key_pair = NULL;
  uchar *ebuffer = NULL;
  char  *sbuffer = NULL;
  int qinit = 0, dinit = 0;
  if((fp != NULL) && (key_pairp != NULL)){
    key_pair = ( bf_key_pair_t *)calloc(1, sizeof(bf_key_pair_t));
    if(key_pair != NULL){
      if(!pairing_init_set_str(key_pair->pairing, pairing_descriptionB)){
        int esz = pairing_length_in_bytes_compressed_G1(key_pair->pairing);
        ebuffer = (uchar *)calloc(esz, sizeof(uchar));
        sbuffer = (char *)calloc(DEFIANT_URL_MAX + 1, sizeof(char));
        if((ebuffer != NULL) && (sbuffer != NULL)){
          size_t bytes_read = fread(ebuffer, sizeof(uchar), esz, fp);
          if(INT(bytes_read) == esz){
            element_init_G1(key_pair->Qid, key_pair->pairing);
            qinit = 1;
            element_from_bytes_compressed(key_pair->Qid, ebuffer);
            bytes_read = fread(ebuffer, sizeof(uchar), esz, fp);
            if(INT(bytes_read) == esz){
              element_init_G1(key_pair->Did, key_pair->pairing);
              dinit = 1;
              element_from_bytes_compressed(key_pair->Did, ebuffer);
              bytes_read = fread(sbuffer, sizeof(char), DEFIANT_URL_MAX, fp);
              sbuffer[bytes_read] = '\0';
              key_pair->public_key = sbuffer;
              *key_pairp = key_pair;
              retcode = DEFIANT_OK; 
            } else {
              retcode = DEFIANT_EOF; 
            }
          } else {
            retcode = DEFIANT_EOF; 
          }
        } else {
          retcode = DEFIANT_MEMORY;
        }
      } else {
        retcode = DEFIANT_DATA;
      }
    } else {
      retcode = DEFIANT_MEMORY;
    }
    free(ebuffer); 
    if(retcode != DEFIANT_OK){
      free(sbuffer);
      if(qinit){ element_clear(key_pair->Qid); }
      if(dinit){ element_clear(key_pair->Did); }
      free(key_pair);
      key_pair = NULL;
      *key_pairp = NULL;
    }
  }
  return retcode;
}

static void crc(uchar crcbuff[CRC_OVERHEAD], const uchar *buffer, int buffer_length){
  crc_t crc_obj = crc_init();
  crc_obj = crc_update(crc_obj, (unsigned char *)buffer, buffer_length);
  crc_obj = crc_finalize(crc_obj);
  memcpy(crcbuff, &crc_obj, CRC_OVERHEAD);
}

int bf_encrypt(bf_params_t *params, const char *public_key, const char *buffer, int buffer_length, bf_ciphertext_t** ciphertextp){
  int retcode = DEFIANT_ARGS;
  if((params != NULL) && (public_key != NULL) && (buffer != NULL) && (buffer_length > 0)  && (buffer_length % IBE_BLOCK_SIZE == 0) && (ciphertextp != NULL)){
    int count, p_offset = 0, c_offset = 0, blocks = buffer_length / IBE_BLOCK_SIZE;
    element_t r, gid, gid2r, Qid;
    bf_ciphertext_t* ciphertext = NULL;
    uchar* gid2r2bytes = NULL;
    int gid2r2bytes_size = 0;
    uchar hash1[HASH_DIMENSION + 1];
    uchar hash2[HASH_DIMENSION + 1];
    hash1[HASH_DIMENSION] = '\0';
    hash2[HASH_DIMENSION] = '\0';
    
    element_init_G1(Qid, params->pairing);
    
    element_init_Zr(r, params->pairing);
    element_init_GT(gid, params->pairing);
    element_init_GT(gid2r, params->pairing);
    
    /* choose a random r */
    element_random(r);
    
    ciphertext = bf_create_ciphertext(params, blocks, r);
    if(ciphertext != NULL){
      
      /* compute Qid */
      if(SHA1((const uchar *)public_key, strlen(public_key), (unsigned char *)hash1) != NULL){
        element_from_hash(Qid, hash1, (int)strlen((char *)hash1));
      
        element_pairing(gid, Qid, params->Ppub); 
        element_pow_zn(gid2r, gid, r);   
        
        
        gid2r2bytes_size = element_length_in_bytes(gid2r);
        gid2r2bytes = (uchar*)calloc(gid2r2bytes_size, sizeof(uchar));
        element_to_bytes(gid2r2bytes, gid2r);
        
        if(SHA1(gid2r2bytes, gid2r2bytes_size, (unsigned char *)hash2) != NULL){
          uchar crcbuff[CRC_OVERHEAD] = ""; 
          for(count = 0; count < blocks; p_offset += IBE_BLOCK_SIZE, c_offset += HASH_DIMENSION, count++){
            uchar *c = ciphertext->bytes + c_offset;
            const uchar *m = (const uchar *)buffer +  p_offset;
            int i, j;
            crc(crcbuff, m, IBE_BLOCK_SIZE);
            for(i = 0; i < IBE_BLOCK_SIZE; i++){
              c[i] = m[i]^hash2[i];
            }
            /* add the hash of the checksum */
            for(j = 0; j < CRC_OVERHEAD; j++){
              c[IBE_BLOCK_SIZE + j] = crcbuff[j]^hash2[IBE_BLOCK_SIZE + j];
            }
          }
          *ciphertextp =  ciphertext;
          retcode = DEFIANT_OK;
        }
        free(gid2r2bytes);
      }
    } /* ciphertext != NULL */

    if(retcode != DEFIANT_OK){ bf_free_ciphertext(ciphertext); }

    element_clear(r);
    element_clear(gid);
    element_clear(gid2r);
    element_clear(Qid);
  }
  return retcode;
}

int bf_decrypt(bf_key_pair_t* key_pair, bf_ciphertext_t* ciphertext, uchar *buffer, int buffer_length){
  int retcode = DEFIANT_ARGS, blocks = 0;
  if((buffer_length % IBE_BLOCK_SIZE) != 0){ 
    return retcode; 
  }
  blocks = buffer_length / IBE_BLOCK_SIZE;
  if((key_pair != NULL) && (ciphertext != NULL) && (INT(ciphertext->bytes_length) == (blocks * HASH_DIMENSION))){
    element_t e;
    uchar* e2bytes = NULL;
    int e2bytes_size = 0;
    uchar hash2[HASH_DIMENSION + 1];
    int count, c_offset = 0, p_offset = 0;
    hash2[HASH_DIMENSION] = '\0';
    element_init_GT(e, key_pair->pairing);	
    element_pairing(e, key_pair->Did, ciphertext->rP);
    e2bytes_size = element_length_in_bytes(e);
    e2bytes = (uchar*)calloc(e2bytes_size, sizeof(uchar));
    element_to_bytes(e2bytes, e);
    if(SHA1(e2bytes, e2bytes_size, (unsigned char *)hash2) != NULL){
      int checksum = 0;
      uchar crcbuff_c[CRC_OVERHEAD] = ""; /* sizeof(crc_t) zeros  */
      uchar crcbuff_p[CRC_OVERHEAD] = ""; /* sizeof(crc_t) zeros  */
      for(count = 0; count < blocks; c_offset += HASH_DIMENSION, p_offset += IBE_BLOCK_SIZE, count++){
        uchar *c = ciphertext->bytes + c_offset;
        uchar *b = buffer +  p_offset;
        int i, j;
        for(i = 0; i < IBE_BLOCK_SIZE; i++){
          b[i] = c[i]^hash2[i];
        }
        /* get the checksum of the plaintext */
        crc(crcbuff_p, b, IBE_BLOCK_SIZE);
        /* extract the checksum sent in the ciphertext */
        for(j = 0; j < CRC_OVERHEAD; j++){
          crcbuff_c[j] = c[IBE_BLOCK_SIZE + j]^hash2[IBE_BLOCK_SIZE + j];
          if(crcbuff_c[j] != crcbuff_p[j]){ checksum = 1; }
        }
        /*
        fprintf(stdout, "crc_c(): [%d,%d,%d,%d]\n", crcbuff_c[0], crcbuff_c[1], crcbuff_c[2], crcbuff_c[3]);
        fprintf(stdout, "crc_p(): [%d,%d,%d,%d]\n", crcbuff_p[0], crcbuff_p[1], crcbuff_p[2], crcbuff_p[3]);
        */
      }
      retcode = checksum ? DEFIANT_CRYPTO : DEFIANT_OK;
    }
    element_clear(e);
    free(e2bytes);
  } 
  return retcode;
}


bf_key_pair_t *bf_create_key_pair(const char *public_key, bf_master_key_t *master_key){
  bf_key_pair_t *key_pair = NULL;
  if((public_key != NULL) && (master_key != NULL)){ 
    uchar hash[HASH_DIMENSION + 1];
    hash[HASH_DIMENSION] = '\0';
    bf_key_pair_t * retval = (bf_key_pair_t*)calloc(1, sizeof(bf_key_pair_t));
   
    pairing_init_set_str(retval->pairing, pairing_descriptionB);

    retval->public_key = duplicate(public_key);

    element_init_G1(retval->Qid, retval->pairing);
    element_init_G1(retval->Did, retval->pairing);

    if(SHA1((unsigned char *)public_key, strlen(public_key), (unsigned char *)hash) != NULL){
      element_from_hash(retval->Qid, hash, (int)strlen((char *)hash));
      element_mul_zn(retval->Did, retval->Qid, master_key->s);
      key_pair = retval;
    } else {
      bf_free_key_pair(retval);
    }
  }
  return key_pair;
}

void bf_free_key_pair(bf_key_pair_t *key_pair){
  element_clear(key_pair->Qid);
  element_clear(key_pair->Did);
  free(key_pair->public_key);
  pairing_clear(key_pair->pairing);
  free(key_pair);
}

void bf_info_key_pair(FILE* fp, bf_key_pair_t *key_pair){
  if(fp != NULL){
    if(key_pair != NULL){
      fprintf(fp, "key_pair->public_key = %s\n", key_pair->public_key);
      element_fprintf(fp, "key_pair->Qid = %B\n", key_pair->Qid);
      element_fprintf(fp, "key_pair->Did = %B\n", key_pair->Did);
    } else {
      fprintf(fp, "key pair is NULL\n");
    }
  }
}

bf_master_key_t* bf_create_master_key(void){
  bf_master_key_t* master_key = (bf_master_key_t*)calloc(1, sizeof(bf_master_key_t));
  if(master_key != NULL){
    if(!pairing_init_set_str(master_key->pairing, pairing_descriptionB)){
      element_init_Zr(master_key->s, master_key->pairing);
      element_random(master_key->s);
    } else {
      free(master_key);
      master_key = NULL;
    }
  }
  return master_key;
}

void bf_free_master_key(bf_master_key_t *master_key){
  element_clear(master_key->s);
  pairing_clear(master_key->pairing);
  free(master_key);
}

void bf_info_master_key(FILE* fp, bf_master_key_t *master_key){
  if(fp != NULL){
    if(master_key != NULL){
      element_fprintf(fp, "master_key->s = %B\n", master_key->s);
    } else {
      fprintf(fp, "master key  is NULL\n");
    }
  }
}

bf_params_t* bf_create_params(bf_master_key_t *master_key){
  bf_params_t* params = NULL;
  if(master_key != NULL){ 
    params = (bf_params_t*)calloc(1, sizeof(bf_params_t));
    pairing_init_set_str(params->pairing, pairing_descriptionB);
    element_init_G1(params->P, params->pairing);
    element_init_G1(params->Ppub, params->pairing);
    params->n = 20;
    element_random(params->P);
    element_mul_zn(params->Ppub, params->P, master_key->s);
  }
  return params;
}


void bf_free_params(bf_params_t* params){
  element_clear(params->P);
  element_clear(params->Ppub);
  pairing_clear(params->pairing);
  free(params);
}

void bf_info_params(FILE* fp, bf_params_t *params){
  if(fp != NULL){
    if(params != NULL){
      element_fprintf(fp, "params->P = %B\n", params->P);
      element_fprintf(fp, "params->Ppub = %B\n", params->Ppub);
    } else {
      fprintf(fp, "params  is NULL\n");
    }
  }
}

void bf_info_params64(FILE* fp, bf_params_t *params){
  if(fp != NULL){
    if(params != NULL){
      char *p, *b;
      int retcode = bf_params_to_char64(&p, &b, params);
      if(retcode == DEFIANT_OK){
        fprintf(fp, "params->P = '%s'\n", p);
        fprintf(fp, "params->Ppub = '%s'\n", b);
        free(p);
        free(b);
      } else {
        fprintf(fp, "bf_params_to_char64 failed: %d\n", retcode);
      }
    } else {
      fprintf(fp, "params  is NULL\n");
    }
  }
}



int bf_ciphertext_equal(bf_ciphertext_t* ciphertextA, bf_ciphertext_t* ciphertextB){
  if((ciphertextA != NULL) && (ciphertextB != NULL)){
    int cmp = element_cmp(ciphertextA->rP, ciphertextB->rP);
    if(!cmp){
      if(ciphertextA->bytes_length != ciphertextB->bytes_length){
        return 0;
      } else {
        int i;
        uchar *A = ciphertextA->bytes, *B = ciphertextB->bytes;
        for(i = 0; i < INT(ciphertextA->bytes_length); i++){
          if(A[i] != B[i]){ 
            return 0; 
          }
        }
        return 1;
      }
    } else {
      return 0;
    }
  } else {
    return ciphertextA == ciphertextB;
  }
}

int bf_read_ciphertext(char* b64U, char* b64V, bf_ciphertext_t** ciphertextp, bf_key_pair_t *key_pair){
  int retval = DEFIANT_MEMORY;
  if((key_pair != NULL) && (ciphertextp != NULL) && (b64U != NULL) && (b64V != NULL)){
    int esz = 0, bsz = 0;
    uchar *ebytes = debase64(b64U, &esz);
    uchar *bbytes = debase64(b64V, &bsz);
    bf_ciphertext_t* ciphertext = bf_create_ciphertext_from_bytes(key_pair, ebytes, esz, bbytes, bsz);
    if(ciphertext != NULL){
      *ciphertextp = ciphertext;
      retval = DEFIANT_OK;
    } else {
      retval = DEFIANT_DATA;
    }
    free(ebytes);
    free(bbytes);
  }
  if(retval != DEFIANT_OK){ *ciphertextp = NULL; }
  return retval;
}


int bf_write_ciphertext(char** b64Up, char** b64Vp, bf_ciphertext_t* ciphertext, bf_params_t *params){
  int retval = DEFIANT_MEMORY;
  if((params != NULL) && (ciphertext != NULL) && (b64Up != NULL) && (b64Vp != NULL)){
    int esz = pairing_length_in_bytes_compressed_G1(params->pairing);
    uchar *ebytes = (uchar*)calloc(esz, sizeof(uchar));
    if(ebytes != NULL){
      int b64U_len = 0, b64V_len = 0;
      char *b64U = NULL, *b64V = NULL;
      element_to_bytes_compressed(ebytes, ciphertext->rP);
      b64U = enbase64(ebytes, esz, &b64U_len);
      b64V = enbase64(ciphertext->bytes, ciphertext->bytes_length, &b64V_len);
      if((b64U != NULL) && (b64V != NULL)){
        *b64Up = b64U;
        *b64Vp = b64V;
        retval = DEFIANT_OK;
      }
    }
    free(ebytes);
  }
  if(retval != DEFIANT_OK){ 
    *b64Up = NULL;
    *b64Vp = NULL;
  }
  return retval;
}


bf_ciphertext_t* bf_create_ciphertext_from_bytes(bf_key_pair_t *key_pair, uchar *ebuffer, int ebuffer_length, uchar *buffer, int buffer_length){
  bf_ciphertext_t* ciphertext = NULL;
  if((key_pair != NULL) && (ebuffer != NULL) && (buffer != NULL)){
    int esz = pairing_length_in_bytes_compressed_G1(key_pair->pairing);
    if(esz == ebuffer_length){
      ciphertext = (bf_ciphertext_t*)calloc(1, sizeof(bf_ciphertext_t));
      if(ciphertext != NULL){
        element_init_G1(ciphertext->rP, key_pair->pairing);
        element_from_bytes_compressed(ciphertext->rP, ebuffer);
        ciphertext->bytes = (uchar*)calloc(buffer_length, sizeof(uchar));
        ciphertext->bytes_length = buffer_length;
        memcpy(ciphertext->bytes, buffer, buffer_length);
      }
    }
  }
  return ciphertext;
}

bf_ciphertext_t* bf_create_ciphertext(bf_params_t *params, int blocks, element_t r){
    bf_ciphertext_t* ciphertext = (bf_ciphertext_t*)calloc(1, sizeof(bf_ciphertext_t));
    if(ciphertext != NULL){
      element_init_G1(ciphertext->rP, params->pairing);
      element_mul_zn(ciphertext->rP, params->P, r);    
      ciphertext->bytes_length = blocks * HASH_DIMENSION;
      ciphertext->bytes = (uchar*)calloc(ciphertext->bytes_length, sizeof(uchar));
    }
    return ciphertext;
}


void bf_free_ciphertext(bf_ciphertext_t* ciphertext){
  element_clear(ciphertext->rP);
  free(ciphertext->bytes);
  free(ciphertext);
}



int bf_write_params(FILE* fp, bf_params_t *params){
  int retcode =  DEFIANT_ARGS;
  if((fp != NULL) && (params != NULL)){
    int esz = pairing_length_in_bytes_compressed_G1(params->pairing);
    uchar *ebuffer = (uchar *)calloc(esz, sizeof(uchar));
    if(ebuffer != NULL){
      size_t bytes_written = 0;
      element_to_bytes_compressed(ebuffer, params->P);
      bytes_written = fwrite(ebuffer, sizeof(uchar), esz, fp);
      if(INT(bytes_written) == esz){
        element_to_bytes_compressed(ebuffer, params->Ppub);
        bytes_written = fwrite(ebuffer, sizeof(uchar), esz, fp);
        if(INT(bytes_written) == esz){
            retcode = DEFIANT_OK;
        } else {
          retcode = DEFIANT_EOF;
        }
      }  else {
        retcode = DEFIANT_EOF;
      }
      free(ebuffer);
    } else {
      retcode = DEFIANT_MEMORY;
    }
  }
  return retcode;
}


int bf_read_params(FILE* fp, bf_params_t **paramsp){
  int retcode = DEFIANT_ARGS;
  bf_params_t *params = NULL;
  uchar *ebuffer = NULL;
  int pinit = 0, binit = 0;
  if((fp != NULL) && (paramsp != NULL)){
    params = ( bf_params_t *)calloc(1, sizeof(bf_params_t));
    if(params != NULL){
      if(!pairing_init_set_str(params->pairing, pairing_descriptionB)){
        int esz = pairing_length_in_bytes_compressed_G1(params->pairing);
        ebuffer = (uchar *)calloc(esz, sizeof(uchar));
        if(ebuffer != NULL){
          size_t bytes_read = fread(ebuffer, sizeof(uchar), esz, fp);
          if(INT(bytes_read) == esz){
            element_init_G1(params->P, params->pairing);
            pinit = 1;
            element_from_bytes_compressed(params->P, ebuffer);
            bytes_read = fread(ebuffer, sizeof(uchar), esz, fp);
            if(INT(bytes_read) == esz){
              element_init_G1(params->Ppub, params->pairing);
              binit = 1;
              element_from_bytes_compressed(params->Ppub, ebuffer);
              *paramsp = params;
              retcode = DEFIANT_OK; 
            } else {
              retcode = DEFIANT_EOF; 
            }
          } else {
            retcode = DEFIANT_EOF; 
          }
        } else {
          retcode = DEFIANT_MEMORY;
        }
      } else {
        retcode = DEFIANT_DATA;
      }
    } else {
      retcode = DEFIANT_MEMORY;
    }
    free(ebuffer); 
    if(retcode != DEFIANT_OK){
      if(pinit){ element_clear(params->P); }
      if(binit){ element_clear(params->Ppub); }
      free(params);
      params = NULL;
      *paramsp = NULL;
    }
  }
  return retcode;
}

/* these are for hard coding the params into the client */
int bf_char64_to_params(char* b64P, char* b64Ppub, bf_params_t **paramsp){
  int retcode = DEFIANT_ARGS;
  bf_params_t *params = NULL;
  if((b64P != NULL) && (b64Ppub != NULL) && (paramsp != NULL)){
    params = ( bf_params_t *)calloc(1, sizeof(bf_params_t));
    if(params != NULL){
      if(!pairing_init_set_str(params->pairing, pairing_descriptionB)){
        int esz = pairing_length_in_bytes_compressed_G1(params->pairing);
        int psz = 0, bsz = 0;
        uchar *p = debase64(b64P, &psz);
        uchar *b = debase64(b64Ppub, &bsz);
        if((p != NULL) && (b != NULL) && (esz == psz) && (esz == bsz)){
          element_init_G1(params->P, params->pairing);
          element_init_G1(params->Ppub, params->pairing);
          element_from_bytes_compressed(params->P, p);
          element_from_bytes_compressed(params->Ppub, b);
          free(p);
          free(b);
          *paramsp = params;
          retcode = DEFIANT_OK;
        } else {
          retcode = DEFIANT_DATA;
        }
      } else {
        retcode = DEFIANT_DATA;
      }
    } else {
      retcode = DEFIANT_MEMORY;
    }
  }
  if(retcode != DEFIANT_OK){ free(params);  }
  return retcode;
}


int bf_params_to_char64(char** b64P, char** b64Ppub, bf_params_t *params){
  int retcode = DEFIANT_ARGS;
  if((b64P != NULL) && (b64Ppub != NULL) && (params != NULL)){
    int esz = pairing_length_in_bytes_compressed_G1(params->pairing);
    uchar *ebuffer = (uchar *)calloc(esz, sizeof(uchar));
    if(ebuffer != NULL){
      int psz = 0, bsz = 0;
      char *p = NULL, *b = NULL;
      element_to_bytes_compressed(ebuffer, params->P);
      p = enbase64(ebuffer, esz, &psz);
      element_to_bytes_compressed(ebuffer, params->Ppub);
      b = enbase64(ebuffer, esz, &bsz);
      if((p != NULL) && (b != NULL)){
        *b64P = p;
        *b64Ppub = b;
        retcode = DEFIANT_OK;
      } else {
        retcode = DEFIANT_DATA;
      }
    } else {
      retcode = DEFIANT_MEMORY;
    }
    free(ebuffer);
  }
  return retcode;
}


/* these are for mysql-ing the key_pair  */
int bf_char64_to_key_pair(char *public_key, char* b64Qid, char* b64Did, bf_key_pair_t **key_pairp){
  int retcode = DEFIANT_ARGS;
  bf_key_pair_t *key_pair = NULL;
  if((public_key != NULL) && (b64Qid != NULL) && (b64Did != NULL) && (key_pairp != NULL)){
    key_pair = ( bf_key_pair_t *)calloc(1, sizeof(bf_key_pair_t));
    if(key_pair != NULL){
      if(!pairing_init_set_str(key_pair->pairing, pairing_descriptionB)){
        int esz = pairing_length_in_bytes_compressed_G1(key_pair->pairing);
        int psz = 0, bsz = 0;
        uchar *p = debase64(b64Qid, &psz);
        uchar *b = debase64(b64Did, &bsz);
        if((p != NULL) && (b != NULL) && (esz == psz) && (esz == bsz)){
          key_pair->public_key = duplicate(public_key);
          element_init_G1(key_pair->Qid, key_pair->pairing);
          element_init_G1(key_pair->Did, key_pair->pairing);
          element_from_bytes_compressed(key_pair->Qid, p);
          element_from_bytes_compressed(key_pair->Did, b);
          free(p);
          free(b);
          *key_pairp = key_pair;
          retcode = DEFIANT_OK;
        } else {
          retcode = DEFIANT_DATA;
        }
      } else {
        retcode = DEFIANT_DATA;
      }
    } else {
      retcode = DEFIANT_MEMORY;
    }
  }
  if(retcode != DEFIANT_OK){ free(key_pair);  }
  return retcode;
}

int bf_key_pair_to_char64(char **public_keyp, char** b64Qidp, char** b64Didp, bf_key_pair_t *key_pair){
  int retcode = DEFIANT_ARGS;
  if((public_keyp != NULL) && (b64Qidp != NULL) && (b64Didp != NULL) && (key_pair != NULL)){
    int esz = pairing_length_in_bytes_compressed_G1(key_pair->pairing);
    uchar *ebuffer = (uchar *)calloc(esz, sizeof(uchar));
    if(ebuffer != NULL){
      int psz = 0, bsz = 0;
      char *p = NULL, *b = NULL;
      element_to_bytes_compressed(ebuffer, key_pair->Qid);
      p = enbase64(ebuffer, esz, &psz);
      element_to_bytes_compressed(ebuffer, key_pair->Did);
      b = enbase64(ebuffer, esz, &bsz);
      if((p != NULL) && (b != NULL)){
        *public_keyp = duplicate(key_pair->public_key);
        *b64Qidp = p;
        *b64Didp = b;
        retcode = DEFIANT_OK;
      } else {
        retcode = DEFIANT_DATA;
      }
    } else {
      retcode = DEFIANT_MEMORY;
    }
    free(ebuffer);
  }
  return retcode;
}

