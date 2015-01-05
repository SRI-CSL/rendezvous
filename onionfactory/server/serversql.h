#ifndef _SERVERSQL_H
#define _SERVERSQL_H

#include <stdio.h>
#include <mysql.h>


MYSQL *sdb_connect(FILE* logfp);


  int validate_cookie_64(char* cookie, char* pk, char* did);


long int sdb_fetch_key_pair_id(MYSQL *mysql, char* public_key);  

char *sdb_fetch_private_key(MYSQL *mysql, long int key_pair_id);  

long int sdb_insert_server(MYSQL *mysql, long int key_pair_id);
long int sdb_fetch_server(MYSQL *mysql, long int key_pair_id);



int sdb_increment_server(MYSQL *mysql, long int id);
long int sdb_insert_server_onion_map(MYSQL *mysql, long int server_id, long int onion_id);

#endif  /* _SERVERSQL_H */


