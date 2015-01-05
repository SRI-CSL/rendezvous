#ifndef _FREEDOM_PROTOCOL_H_
#define _FREEDOM_PROTOCOL_H_

#include "freedom.h"


enum freedom_request { FR_IGNORE = 0, FR_REPLY = 1, FR_UPDATE = 2};


/* currently decide according to the existence of a query string */
int is_freedom_request(request_rec *r, char **secretp);

/* proof of concept only */  
int serve_freedom_response(request_rec *r, char *secret);

/* serve the configured error document */
int serve_error_response(request_rec *r);

/* see if the update task needs to be run; if so run it; 0 indicates it didn't run; 1 indicates it did */
int freedom_update_task_check(request_rec *r);

#endif

