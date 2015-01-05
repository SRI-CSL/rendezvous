#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "serversql.h"
#include "utils.h"

static char *dbhost   = "localhost";
static char *dbuser   = "onionserver";
static char *dbpasswd = "onionserver4mysql";
static char *dbname   = "onionfactory";


#define LONG_DIGITS ((CHAR_BIT * sizeof(long int) + 2) / 3)


MYSQL *sdb_connect(FILE* logfp){
  MYSQL *mysql = mysql_init(NULL);
  if (mysql == NULL) {
    fprintf(logfp, "sdb_connect(mysql_init) error %u: %s\n", mysql_errno(mysql), mysql_error(mysql));
    return NULL;
  }
  
  if (mysql_real_connect(mysql, dbhost, dbuser, dbpasswd, dbname, 0, NULL, 0) == NULL) {
    fprintf(logfp, "sdb_connect(mysql_real_connect) error %u: %s\n", mysql_errno(mysql), mysql_error(mysql));
    return NULL;
  }
  return mysql;
}




long int sdb_fetch_key_pair_id(MYSQL *mysql, char* public_key){
  long int retval = -1;
  if((mysql != NULL) && (public_key != NULL)){
    char *format = "SELECT key_pair_id from key_pair WHERE public_key='%s'";
    size_t query_length = strlen(format) + strlen(public_key) + 1;
    char *query = (char *)calloc(query_length, sizeof(char));
    if(query != NULL){
      int retcode;
      snprintf(query, query_length, format, public_key);
      retcode = mysql_query(mysql, query);
      if(retcode == 0){
        MYSQL_RES *result = mysql_store_result(mysql);
        MYSQL_ROW row = mysql_fetch_row(result);
        if(row != NULL){
          retval = atol(row[0]);
          //fprintf(stderr, "key_pair_id = %ld\n", retval);
        }
        mysql_free_result(result);
      }
      free(query);
    }
  }
  return retval;
}
  
char * sdb_fetch_private_key(MYSQL *mysql, long int key_pair_id){
  char *retval = NULL;
  if((mysql != NULL) && (key_pair_id > 0)){
    char *format = "SELECT Did from key_pair WHERE key_pair_id=%ld";
    size_t query_length = strlen(format) + LONG_DIGITS + 1;
    char *query = (char *)calloc(query_length, sizeof(char));
    if(query != NULL){
      int retcode;
      snprintf(query, query_length, format, key_pair_id);
      retcode = mysql_query(mysql, query);
      if(retcode == 0){
        MYSQL_RES *result = mysql_store_result(mysql);
        MYSQL_ROW row = mysql_fetch_row(result);
        if(row != NULL){
          retval = duplicate(row[0]);
        }
        mysql_free_result(result);
      }
      free(query);
    }
  }
  return retval;
}


long int sdb_fetch_server(MYSQL *mysql, long int key_pair_id){
  long int retval = -1;
  if((mysql != NULL) && (key_pair_id > 0)){
    char *format = "SELECT server_id from server WHERE key_pair_id=%ld";
    size_t query_length = strlen(format) + LONG_DIGITS + 1;
    char *query = (char *)calloc(query_length, sizeof(char));
    if(query != NULL){
      int retcode;
      snprintf(query, query_length, format, key_pair_id);
      retcode = mysql_query(mysql, query);
      if(retcode == 0){
        MYSQL_RES *result = mysql_store_result(mysql);
        MYSQL_ROW row = mysql_fetch_row(result);
        if(row != NULL){
          retval = atol(row[0]);
          //fprintf(stderr, "server_id = %ld\n", retval);
        }
        mysql_free_result(result);
      }
      free(query);
    }
  }
  return retval;
}

long int sdb_insert_server(MYSQL *mysql, long int key_pair_id){
  long int retval = -1;
  if((mysql != NULL) && (key_pair_id > 0)){
    char *format = "insert into server (key_pair_id, last_time) values (%ld, now())";
    size_t query_length = strlen(format) + LONG_DIGITS + 1;
    char *query = (char *)calloc(query_length, sizeof(char));
    if(query != NULL){
      int retcode;
      snprintf(query, query_length, format, key_pair_id);
      retcode = mysql_query(mysql, query);
      if(retcode == 0){
        retval = mysql_insert_id(mysql);
        //fprintf(stderr, "server_id = %ld\n", retval);
      }
      free(query);
    }
  }
  return retval;
}



int sdb_increment_server(MYSQL *mysql, long int id){
  int retcode = -1;
  if((mysql != NULL) && (id >= 0)){
    char *format = "update server set requests = requests + 1, last_time = now() where server_id = %ld";
    size_t query_length = strlen(format) + LONG_DIGITS + 1;
    char *query = (char *)calloc(query_length, sizeof(char));
    if(query != NULL){
      snprintf(query, query_length, format, id);
      retcode = mysql_query(mysql, query);
      free(query);
    }
  }
  return retcode;
}




long int sdb_insert_server_onion_map(MYSQL *mysql, long int server_id, long int onion_id){
  long int retval = -1;
  if((mysql != NULL) && (server_id != -1) && (onion_id != -1)){
    char *format = "insert into server_onion_map (server_id, onion_id) values (%ld, %ld)";
    size_t query_length = strlen(format) + (2 * LONG_DIGITS) + 1;
    char *query = (char *)calloc(query_length, sizeof(char));
    if(query != NULL){
      int retcode;
      snprintf(query, query_length, format, server_id, onion_id);
      retcode = mysql_query(mysql, query);
      if(retcode == 0){
        retval = mysql_insert_id(mysql);
        //fprintf(stderr, "server_id = %ld\n", retval);
      }
      free(query);
    }
  }
  return retval;
}
