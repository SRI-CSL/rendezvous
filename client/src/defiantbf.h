#ifndef _DEFIANTBF_H
#define _DEFIANTBF_H

/* Boneh Franklin BasicIdent Augmented with Checksums */

/* 
 * Ian says for the time being we will assume that there is a fixed pairing in the background (i.e. compiled in) 
 * which means if we get the time and inclination we can move the pairing_t out into a static location
 *
*/

#include <pbc/pbc.h>
#include "crc.h"
#include "defianttypes.h"

/* currently 4  */
#define CRC_OVERHEAD    ((int)sizeof(crc_t))
#define HASH_DIMENSION  20
/* currently 16 */
#define IBE_BLOCK_SIZE  (HASH_DIMENSION - CRC_OVERHEAD)


typedef struct _bf_master_key_t {
  pairing_t pairing;
  element_t s; 
} bf_master_key_t;



typedef struct _bf_params_t {
  pairing_t pairing;
  element_t P; 
  element_t Ppub;
  int n;
} bf_params_t;


typedef struct _bf_key_pair_t {
  pairing_t pairing;                            
  char *public_key;
  element_t Qid;
  element_t Did; 
} bf_key_pair_t;


typedef struct _bf_ciphertext_t {
  element_t rP;
  uchar* bytes;
  size_t bytes_length;
} bf_ciphertext_t;

#ifdef __cplusplus
extern "C" {
#endif

  bf_master_key_t* bf_create_master_key(void);
  void bf_free_master_key(bf_master_key_t *master_key);
  void bf_info_master_key(FILE* fp, bf_master_key_t *master_key);
  int bf_write_master_key(FILE* fp, bf_master_key_t *master_key);
  int bf_read_master_key(FILE* fp, bf_master_key_t **master_keyp);


  bf_params_t* bf_create_params(bf_master_key_t *master_key);
  void bf_free_params(bf_params_t* params);
  void bf_info_params(FILE* fp, bf_params_t* params);
  void bf_info_params64(FILE* fp, bf_params_t* params);
  int bf_write_params(FILE* fp, bf_params_t *params);
  int bf_read_params(FILE* fp, bf_params_t **paramsp);

  /* these are for hard coding the params into the client */
  int bf_char64_to_params(char* b64P, char* b64Ppub, bf_params_t **paramsp);
  int bf_params_to_char64(char** b64P, char** b64Ppub, bf_params_t *params);
  
  bf_key_pair_t *bf_create_key_pair(const char *public_key, bf_master_key_t *master_key);
  void bf_free_key_pair(bf_key_pair_t *key_pair);
  void bf_info_key_pair(FILE* fp, bf_key_pair_t *key_pair);
  int bf_write_key_pair(FILE* fp, bf_key_pair_t *key_pair);
  int bf_read_key_pair(FILE* fp, bf_key_pair_t **key_pairp);
  
  /* these are for msql-ing and perhaps alose using as shared secrets */
  int bf_char64_to_key_pair(char *public_key, char* b64Qid, char* b64Did, bf_key_pair_t **key_pairp);
  int bf_key_pair_to_char64(char **public_keyp, char** b64Qidp, char** b64Didp, bf_key_pair_t *key_pair);
  
  /* buffer_length must be an exact multiple of IBE_BLOCK_SIZE */
  int bf_encrypt(bf_params_t *params, const char *public_key, const char *buffer, int buffer_length, bf_ciphertext_t** ciphertextp);
  int bf_decrypt(bf_key_pair_t* key_pair, bf_ciphertext_t* ciphertext,  uchar *buffer, int buffer_length);
  
  bf_ciphertext_t* bf_create_ciphertext(bf_params_t *params, int blocks, element_t r);
  /* from stuff over the wire */
  bf_ciphertext_t* bf_create_ciphertext_from_bytes(bf_key_pair_t *key_pair, uchar *ebuffer, int ebuffer_length, uchar *buffer, int buffer_length);
  void bf_free_ciphertext(bf_ciphertext_t* ciphertext);
  /* keep this simple at first  C = <U, V> and is transmitted in two blobs via query strings */
  int bf_read_ciphertext(char* b64U, char* b64V, bf_ciphertext_t** ciphertextp, bf_key_pair_t *key_pair);
  int bf_write_ciphertext(char** b64U, char** b64V, bf_ciphertext_t* ciphertext, bf_params_t *params);
  
  /* for testing */
  int bf_ciphertext_equal(bf_ciphertext_t* ciphertextA, bf_ciphertext_t* ciphertextB);
  
#ifdef __cplusplus
}	/*  extern "C" */

#endif /* __cplusplus */




#endif /* _DEFIANTBF_H */

