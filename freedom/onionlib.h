#ifndef _ONIONLIB_H
#define _ONIONLIB_H
#include "freedom.h"
#include "freedom_config.h"
#include "onion.h"

int apr_peel_collection_onion(onion_t onion_in, int* onioncp, onion_t** onionvp);

/* N.B. only use this in a process that has already initialized the server_update_mutex */
apr_array_header_t* onionfile_to_array(server_rec* s, freedom_server_config *svr_cfg, const char* path, apr_pool_t* p);

onion_t apr_fetch_onions(char* cookie, server_rec* s, FILE* public_key_fp, char* onion_url, char* tor_proxy, long tor_proxy_port, int tor_proxy_protocol);

apr_status_t signed_collection_to_file(server_rec* s, onion_t onion, const char* path, apr_pool_t* pool);

#endif
