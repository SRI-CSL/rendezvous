#include <stdio.h>
#include <string.h>
#include "defiantbf.h"
#include "utils.h"
#include "defiantclient.h"

int print_vectors             = 1;
int write_and_read_ciphertext = 1;
int write_and_read_master     = 1;
int write_and_read_pair       = 1;
int write_and_read_params     = 1;
int write_and_read_params64   = 1;
#define BLOCKS 4
#define BUFFER_SIZE  (BLOCKS * IBE_BLOCK_SIZE)

int main(int argc, char **argv){
  static const char public_key[] = "vm06.csl.sri.com";

  uchar buffer_in[BUFFER_SIZE + 1];
  generate_random_key(buffer_in, BUFFER_SIZE);
  buffer_in[BUFFER_SIZE] = '\0';

  bf_master_key_t* master_key = bf_create_master_key();

  if(master_key != NULL){
    bf_key_pair_t *key_pair = bf_create_key_pair(public_key, master_key);
    bf_params_t* params = bf_create_params(master_key);

    
    if((params != NULL) && (key_pair != NULL)){
      bf_ciphertext_t* ciphertextA = NULL;
      int retcode = bf_encrypt(params, public_key, (const char *)buffer_in, BUFFER_SIZE, &ciphertextA);

      if(retcode != DEFIANT_OK){
        fprintf(stdout, "bf_encrypt FAILED, retcode = %d\n", retcode);
        exit(0);
      } else {
        uchar buffer_out[BUFFER_SIZE + 1];
        buffer_out[BUFFER_SIZE] = '\0';
        retcode = bf_decrypt(key_pair, ciphertextA, buffer_out, BUFFER_SIZE);
        if(retcode != DEFIANT_OK){
          fprintf(stdout, "bf_decrypt FAILED, retcode = %d\n", retcode);
          exit(0);
        } else {

          if(print_vectors){
            int i;
            for(i = 0; i < BUFFER_SIZE; i++){
              fprintf(stdout, "[%d] %d %d\n", i, buffer_in[i], buffer_out[i]);
            }
          }

          fprintf(stdout, "OK = %d\n",strncmp((char *)buffer_in,(char *)buffer_out, BUFFER_SIZE));


        }

        if(write_and_read_ciphertext){                                                          
          char *b64U = NULL, *b64V = NULL;
          int retcode = bf_write_ciphertext(&b64U, &b64V, ciphertextA, params);
          fprintf(stderr, "bf_write_ciphertext retcode = %d\n", retcode); 
          fprintf(stderr, "b64U = %s\n", b64U);
          fprintf(stderr, "b64V = %s\n", b64V);
          if(retcode == DEFIANT_OK){
            bf_ciphertext_t* ciphertextB = NULL;
            retcode = bf_read_ciphertext(b64U, b64V, &ciphertextB, key_pair);
            fprintf(stderr, "bf_read_ciphertext retcode = %d\n", retcode); 
            if(retcode == DEFIANT_OK){
              int equal = bf_ciphertext_equal(ciphertextA, ciphertextB);
              fprintf(stderr, "bf_ciphertext_equal = %d\n", equal); 
            }
            bf_free_ciphertext(ciphertextB);
          }
          free(b64U);
          free(b64V);
        }

      
        
        if(write_and_read_master){
          int retcode;
          char *masterfile = "master_key.bin";
          FILE *fp;
          fp = fopen(masterfile, "wb");
          if(fp != NULL){
            retcode = bf_write_master_key(fp, master_key);
            fprintf(stderr, "bf_write_master_key = %d\n", retcode);
            fclose(fp);
            fp = fopen(masterfile, "rb");
            if(fp != NULL){
              bf_master_key_t* master_key_copy = NULL;
              retcode = bf_read_master_key(fp, &master_key_copy);
              fprintf(stderr, "bf_read_master_key = %d\n", retcode);
              fclose(fp);
              if(master_key_copy != NULL){
                element_fprintf(stderr, "master_key->s = %B\n", master_key->s);
                element_fprintf(stderr, "master_key_copy->s = %B\n", master_key_copy->s);
                fprintf(stderr, "master keys cmp: %d\n", element_cmp(master_key_copy->s, master_key->s));
                bf_free_master_key(master_key_copy);
              }
            }
          }
        }
        
        if(write_and_read_params){
          int retcode;
          char *keyfile = "params.bin";
          FILE *fp;
          fp = fopen(keyfile, "wb");
          if(fp != NULL){
            retcode = bf_write_params(fp, params);
            fprintf(stderr, "bf_write_params = %d\n", retcode);
            fclose(fp);
            fp = fopen(keyfile, "rb");
            if(fp != NULL){
              bf_params_t* params_copy = NULL;
              retcode = bf_read_params(fp, &params_copy);
              fprintf(stderr, "bf_read_params = %d\n", retcode);
              fclose(fp);
              if(params_copy != NULL){
                int cmpP = element_cmp(params_copy->P, params->P);
                int cmpB = element_cmp(params_copy->Ppub, params->Ppub);
                fprintf(stderr, "params P cmp: %d\n", cmpP);
                fprintf(stderr, "params Ppub cmp: %d\n", cmpB);
                bf_info_params(stderr, params);
                bf_info_params(stderr, params_copy);
                bf_free_params(params_copy);
              }
            }
          }
        }

        if(write_and_read_pair){
          int retcode;
          char *keyfile = "key_pair.bin";
          FILE *fp;
          fp = fopen(keyfile, "wb");
          if(fp != NULL){
            retcode = bf_write_key_pair(fp, key_pair);
            fprintf(stderr, "bf_write_key_pair = %d\n", retcode);
            fclose(fp);
            fp = fopen(keyfile, "rb");
            if(fp != NULL){
              bf_key_pair_t* key_pair_copy = NULL;
              retcode = bf_read_key_pair(fp, &key_pair_copy);
              fprintf(stderr, "bf_read_key_pair = %d\n", retcode);
              fclose(fp);
              if(key_pair_copy != NULL){
                int cmpQ = element_cmp(key_pair_copy->Qid, key_pair->Qid);
                int cmpD = element_cmp(key_pair_copy->Did, key_pair->Did);
                fprintf(stderr, "key pair Qid cmp: %d\n", cmpQ);
                fprintf(stderr, "key pair Did cmp: %d\n", cmpD);
                bf_info_key_pair(stderr, key_pair);
                bf_info_key_pair(stderr, key_pair_copy);
                bf_free_key_pair(key_pair_copy);
              }
            }
          }
        }
        
        if(write_and_read_params64){
          char *p64, *b64;
          int retcode = bf_params_to_char64(&p64, &b64, params);
          if(retcode == DEFIANT_OK){
            bf_params_t* params_copy = NULL;
            fprintf(stderr, "params->P = '%s'\n", p64);
            fprintf(stderr, "params->Ppub = '%s'\n", b64);
            retcode = bf_char64_to_params(p64, b64, &params_copy);
            if((retcode == DEFIANT_OK) && (params_copy != NULL)){
              int cmpP = element_cmp(params_copy->P, params->P);
              int cmpB = element_cmp(params_copy->Ppub, params->Ppub);
              bf_info_params(stderr, params);
              bf_info_params(stderr, params_copy);
              bf_free_params(params_copy);
              fprintf(stderr, "params P cmp: %d\n", cmpP);
              fprintf(stderr, "params Ppub cmp: %d\n", cmpB);
            }
            free(p64);
            free(b64);
          }
        }
        
        bf_free_ciphertext(ciphertextA);
        bf_free_master_key(master_key);
        bf_free_params(params);
        bf_free_key_pair(key_pair);
        
        
      }
      
    }
    
  }
  
  return 0;

}
