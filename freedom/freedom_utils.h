#ifndef _FREEDOM_UTILS_H_
#define _FREEDOM_UTILS_H_

#include "freedom.h"
#include "freedom_config.h"

int reload_reply_list_file(request_rec *r);

apr_time_t get_mtime(const char* path, apr_pool_t* p);

int freedom_seconds_since_update(freedom_server_config *svr_cfg, request_rec *r);

int apr_is_defiant_request(bf_key_pair_t* key_pair, apr_uri_t* urip, char** passwordp);

#endif

