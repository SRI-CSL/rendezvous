#include <stdio.h>
#include <stdlib.h>
#include <mysql.h>

#include "serverlib.h"
#include "serversql.h"


int main(int argc, char** argv){
  char* public_key = "vm06.csl.sri.com";
  FILE* logfp = stderr; 
  MYSQL *mysql = sdb_connect(logfp);

  if(argc > 1){ public_key = argv[1]; }

  if(mysql != NULL){
    int index;
    long int key_pair_id = sdb_fetch_key_pair_id(mysql, public_key);  

    if(key_pair_id == -1){
      fprintf(stderr, "Don't know server %s\n",  public_key);
    } else {
      long int server_id = sdb_fetch_server(mysql, key_pair_id);
      if(server_id == -1){
        fprintf(stderr, "New server %s phoning home!\n",  public_key);
        server_id = sdb_insert_server(mysql, key_pair_id);
      } 
      for(index = 0; index < 10; index++){
        int retcode = sdb_increment_server(mysql, server_id);
        fprintf(stderr, "++ %d\n", retcode);
      }
      fprintf(stderr, "BINGO server %ld; key_pair  %ld\n", server_id, key_pair_id);
    }
  }
  mysql_close(mysql);
  return 0;
}




