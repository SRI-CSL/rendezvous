#include <stdio.h>
#include <stdlib.h>
#include <mysql.h>

void flag(FILE* logfp, int debug, char* msg);

char* server_fetchenv(char* key);

void bApache();

void server_dumpenv(FILE* logfp);

void serve_onions(FILE* private_key_fp, FILE* public_key_fp, MYSQL *mysql, long int server_id, FILE* logfp, int debug, int timing);

int validate_server(MYSQL *mysql, char *cookie, long int *key_pair_idp);


