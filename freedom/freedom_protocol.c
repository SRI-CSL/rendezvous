#include "freedom_config.h"
#include "freedom_protocol.h"
#include "freedom_utils.h"
#include "cryptlib.h"
#include "onion.h"
#include "onionlib.h"
#include "jpeg_steg.h"
#include "defiantclient.h"
#include "defiantcookie.h"
#include "defiantconstants.h"
#include "defiantbf.h"

extern module AP_MODULE_DECLARE_DATA freedom_module;

/* keep this on during DETER */
static int debug = 1;

int is_freedom_request(request_rec *r, char**secretp){
  int errcode = DEFIANT_ARGS;
  if((secretp != NULL)  && (r != NULL)){
    freedom_server_config *svr_cfg = ap_get_module_config(r->server->module_config, &freedom_module);
    apr_uri_t uri = r->prev->parsed_uri;
    *secretp = NULL;
    if((svr_cfg != NULL) && (svr_cfg->key_pair != NULL)){
      errcode = apr_is_defiant_request(svr_cfg->key_pair, &uri, secretp);
    } else {
      RLOG(r, "is_freedom_request: key_pair MISSING? (%s)", uri.query); 
    }
    if(debug){
      RLOG(r, "is_freedom_request: uri.query = %s", uri.query); 
      RLOG(r, "is_freedom_request: errcode = %d error string = %s", errcode, defiant_strerror(errcode));      
    }
    if((errcode == DEFIANT_OK) && (*secretp != NULL)){
      char *secret = *secretp;
      int i = 0, secretlen = strlen(secret);
      if(!isRandomPasswordEx(secret, secretlen)){
        RLOG(r, "is_freedom_request: secret contains suspicious chars: %s", secret); 
        return FR_IGNORE;
      }
      RLOG(r, "is_freedom_request: password = %s", secret);     
      return FR_REPLY;  
    } 
  }
  return FR_IGNORE;
}

static void prevent_chunking(request_rec *r){
  const int debug = 0;
  ap_filter_t *next;
  next = r->output_filters;
  while (next) {
    if(debug)RLOG(r, "Looking at filter called %s", next->frec->name);
    if(!strcmp(next->frec->name, "deflate")){
      if(debug)RLOG(r, "Removing filter called %s", next->frec->name);
      ap_remove_output_filter(next);
    }
    next = next->next;
  }
}

/* quick 'n dirty method of serving a "random" element of the list */
static int choose(int min, int max){
  int retval = min;
  unsigned char byties[1];
  srand(apr_time_now());
  apr_generate_random_bytes(byties, sizeof(byties));
  retval += (*byties * (max - min)) / 255;
  return retval;
}



static onion_t random_response(request_rec *r){
  int rindex = -1;
  onion_t retval = NULL;
  freedom_server_config *svr_cfg = ap_get_module_config(r->server->module_config, &freedom_module);
  apr_array_header_t* responses = svr_cfg->rlf_array;
  if((responses != NULL) && 0 < responses->nelts){
    onion_t* list = (onion_t*)responses->elts;
    rindex = choose(0, responses->nelts - 1);
    retval = list[rindex];
  } 
  if(retval != NULL){
    RLOG(r, "serve_freedom_response: served response[%d] of size %" PRIu64, rindex, ONION_SIZE(retval)); 
  } else {
    RLOG(r, "serve_freedom_response: no onions available: %d", (responses == NULL ? -1 : responses->nelts)); 
  }
  return retval;
}

static int steg_embed_onion(request_rec *r, freedom_server_config *svr_cfg, const char* secret, const uchar* encrypted_onion, size_t encrypted_onion_size, int* bytes_writtenp){
  int retval = DEFIANT_DATA;
  char* imagedir = NULL;
  //hard coded till the circle becomes unbroken
  char* cover_image = NULL;
  if((svr_cfg != NULL) && ((imagedir = svr_cfg->image_library_directory) != NULL)){
    cover_image = random_file(imagedir);
  }
  //"/etc/apache2/mod_freedom_data/images/buffalo.jpg";
  if(cover_image != NULL){
    char* bytes = NULL;
    size_t bytes_sz = 0;
    RLOG(r, "steg_embed_onion using RANDOM image: %s", cover_image);
    int errcode =  embed(secret, (char *)encrypted_onion, encrypted_onion_size, cover_image, &bytes, &bytes_sz);
    if(errcode == DEFIANT_OK){
      int bytes_written = 0;
      apr_off_t content_length  = bytes_sz;
      /* remove the deflate filter if it is lurking there */
      prevent_chunking(r);
      ap_set_content_type(r, "image/jpeg");
      ap_set_content_length(r, content_length); 
      ap_set_etag(r);
      ap_set_accept_ranges(r);
      bytes_written = ap_rwrite(bytes, content_length, r);
      ap_rflush(r);
      if(bytes_written != bytes_sz){
        RERR(r, "ap_rwrite of an steg embedded onion of size %zu returned %d", bytes_sz, bytes_written);
      } else {
        RLOG(r, "ap_rwrite wrote an steg embedded onion of size %d, status = %d", bytes_written, r->status);
      }
      free(bytes);
      *bytes_writtenp = bytes_written;
      retval = DEFIANT_OK;
    }
  }
  return retval;
}


/* proof of concept only */  
int serve_freedom_response(request_rec *r, char *secret){
  freedom_server_config *svr_cfg = ap_get_module_config(r->server->module_config, &freedom_module);
  const onion_t resp = random_response(r);
  int bytes = 0;
    if(resp != NULL){
      int encrypted_onion_size = 0;
      uchar *encrypted_onion = defiant_pwd_encrypt(secret, resp, ONION_SIZE(resp), &encrypted_onion_size); 
      if((encrypted_onion != NULL) && (encrypted_onion_size > 0)){
        int errcode, bytes_written = 0, bytes_wanted = encrypted_onion_size;
        /* must set status *before* pushing stuff down the pipe */
        r->status  = HTTP_OK;
        /* first try and embed the onion in an jpeg */
        errcode = steg_embed_onion(r, svr_cfg, secret, encrypted_onion, encrypted_onion_size, &bytes_written);
        if(errcode != DEFIANT_OK){
          /* serve up the raw onion instead */
          ap_set_content_type(r, "image/gif");
          ap_set_content_length(r, bytes_wanted);
          bytes_written = ap_rwrite(encrypted_onion, bytes_wanted, r);
          if(bytes_written != bytes_wanted){
            RERR(r, "ap_rwrite of an encrypted onion of size %d returned %d", bytes_wanted, bytes_written);
          } else {
            RLOG(r, "ap_rwrite wrote an encrypted onion of size %d, status = %d", bytes_written, r->status);
          }
        }
        free(encrypted_onion);
        bytes = bytes_written;
      }
    } else {
      bytes = serve_error_response(r); 
    }
    return bytes > 0 ? OK : HTTP_INTERNAL_SERVER_ERROR;
}



int serve_error_response(request_rec *r){
  if(r->filename == NULL){ 
    /* is this what would happen if the file was missing? CHECK THIS */
    RERR(r, "mod_freedom got given a bad request. Check your ErrorDocument %s!", "settings");
    return HTTP_INTERNAL_SERVER_ERROR;
  } else {
    apr_file_t *fd;
    apr_size_t size;
    apr_status_t retcode;
    ap_set_content_type(r, "text/html;charset=ascii");
    ap_set_content_length(r, r->finfo.size);
    if(r->finfo.mtime){
      char* datestring = apr_pcalloc(r->pool, APR_RFC822_DATE_LEN);
      apr_rfc822_date(datestring, r->finfo.mtime);
      apr_table_setn(r->headers_out, "Last-Modified", datestring);
    }
    retcode = apr_file_open(&fd, r->filename, APR_READ|APR_SHARELOCK|APR_SENDFILE_ENABLED, APR_OS_DEFAULT, r->pool);
    if(retcode != APR_SUCCESS){
      RERR(r, "mod_freedom can't open %s. Check your ErrorDocument directive and the file it points to!", r->filename);
      /* can't 404 here for (semi-) obvious reasons */
      return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* could/should check size and retcode */
    retcode = ap_send_fd(fd, r, 0, r->finfo.size, &size);

    /* this is optional; so don't fret */
    apr_file_close(fd);

    return OK;
  } 
  
}


static int _freedom_update_task(request_rec *r, freedom_server_config *svr_cfg){
  apr_status_t status = APR_EOF;
  onion_t signed_collection = NULL;
  time_t stop, start =  time(NULL);
  char* cookie = NULL;
  const char *filepath = ap_server_root_relative(r->pool, svr_cfg->defiance_public_key_path);
  FILE* defiant_public_key_fp = fopen(filepath, "r");
  RLOG(r, "_freedom_update_task: Starting@%ld", start);
  if(defiant_public_key_fp == NULL){
    RERR(r, "_freedom_update_task: Couldn't open public key %s  at %s because %s!",  svr_cfg->defiance_public_key_path, filepath, strerror(errno));
  } else {
    cookie = construct_cookie(svr_cfg->key_pair);
    signed_collection = apr_fetch_onions(cookie, r->server, defiant_public_key_fp, svr_cfg->tor_hidden_service, svr_cfg->tor_proxy_address, svr_cfg->tor_proxy_port, svr_cfg->tor_proxy_protocol);
    if(signed_collection != NULL){
      /* n.b. the onion will have already been verified */
      status = signed_collection_to_file(r->server, signed_collection, svr_cfg->rlf_path, r->pool);
      free(signed_collection);
    } else {
      RLOG(r, "_freedom_update_task: signed_collection is NULL%s", "!");
    }
    free(cookie);
    fclose(defiant_public_key_fp);
  }
  stop = time(NULL);
  RLOG(r, "_freedom_update_task: Stopping@%ld", stop);
  RLOG(r, "_freedom_update_task: Delta T: %ld", stop - start);
  return status == APR_SUCCESS;
}


static int freedom_update_task(request_rec *r, freedom_server_config *svr_cfg){
  apr_status_t status = 0;
  if(svr_cfg->initialized_with_no_issues){
    status = freedom_process_init(r->server, svr_cfg);
    if(status == APR_SUCCESS){
      status =  apr_global_mutex_trylock(svr_cfg->server_update_mutex);
      if(APR_STATUS_IS_EBUSY(status)){
        RLOG(r, "freedom_update_task global lock BUSY %d!", status);
        return 0;
      } else {
        int retval = _freedom_update_task(r, svr_cfg);
        apr_global_mutex_unlock(svr_cfg->server_update_mutex);
        return retval;
      }
    }
  } else {
    RERR(r, "Skipping update; server not initialized completely  %d", svr_cfg->initialized_with_no_issues);
  }
  return status == APR_SUCCESS;
}



int freedom_update_task_check(request_rec *r){
  int retval = 0;
  if(r != NULL){
    freedom_server_config *svr_cfg = ap_get_module_config(r->server->module_config, &freedom_module);
    int last = freedom_seconds_since_update(svr_cfg, r);
    int minutes = last/60;
    int hours = minutes/60;
    int days = hours/24;
    int interval = svr_cfg->update_interval;
    RLOG(r, 
         "freedom_update_task_check[%d]: seconds: %d, minutes: %d, hours: %d, days: %d; all since the last update.",
         interval, last, minutes, hours, days);
    if(last > interval){ 
      retval = freedom_update_task(r, svr_cfg);
      RLOG(r, "freedom_update_task_check RAN: uptime %d retval %d", last, retval);
    }
  }
  return retval;
}

