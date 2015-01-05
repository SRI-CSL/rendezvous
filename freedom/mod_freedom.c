#include "freedom.h"
#include "freedom_config.h"
#include "freedom_protocol.h"
#include "freedom_utils.h"
#include "cryptlib.h"

static void freedom_hooks(apr_pool_t *pool);

extern const command_rec freedom_commands[];

module AP_MODULE_DECLARE_DATA freedom_module = {
  STANDARD20_MODULE_STUFF,
  NULL,
  NULL,
  freedom_create_server_config,
  NULL,
  freedom_commands,
  freedom_hooks
};


static int freedom_handler(request_rec *r){
  
  if(!r->handler || strcmp(r->handler, "freedom")){ return DECLINED; }

  if(r->method_number != M_GET){ return HTTP_METHOD_NOT_ALLOWED; }
  
  RLOG(r, "freedom_handler handling request; status = %d;  filename = %s", r->status, r->filename);
      
 
  /* a direct request for the error document - stranger things have happened */
  if(r->prev == NULL){
    RLOG(r, "freedom_handler passing the buck on a direct request to: %s", r->filename);
    return DECLINED;
  }  else {
    /* OK we are handling a genuine 404 request */
    int status;

    /* this will be Alice's password if this is a valid defiance request */
    char* secret = NULL;

    int reqtype = is_freedom_request(r, &secret);

    RLOG(r, "freedom_handler switching on %d request", reqtype);
    
    switch(reqtype){
    case FR_REPLY: {

      /* update the onion list, if it is stale */
      int overeager, update = freedom_update_task_check(r);

      /* reload the onion list, if it is new */
      int count = reload_reply_list_file(r);

      if(count != 0){
        RLOG(r, "freedom_handler reloaded %d onions", count);
      } else {
        RLOG(r, "freedom_handler *not* reloading onions (%d)", count);
      }

      status = serve_freedom_response(r, secret);
      break;

    }
    case FR_IGNORE:
    default:
      /* we merely serve the error document */
      status = serve_error_response(r);
    }
    free(secret);
    RLOG(r, "freedom_handler: RETURNING status = %d; r->status %d", status, r->status);
    return status;
  }

}

static void freedom_hooks(apr_pool_t *pool){
  ap_hook_handler(freedom_handler, NULL, NULL, APR_HOOK_MIDDLE);
}


