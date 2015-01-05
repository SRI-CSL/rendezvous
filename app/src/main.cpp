#include "rendezvous.h"
#include "dancer.h"
#include "stegospawner.h"
#include "defiantrequest.h"


char instructions[] =
  "-h --help  print these instructions\n"
  "-p --proxy  <proxyserver:proxyport>\n"
  "-g --geometry <width>x<height>\n"
  "-s --server <mod_freedom server hostname>\n"
  "-c --curl  use libcurl rather than the QtNetwork library\n"
  "-l --ssl  make the ssl checkbox default to be true\n"
  "-n --no-dancing skip the dance; IPNPORT4STEGOTORUS must be set\n"
  "-d --debug\n"
  "-t --proxytype  <curl_proxy_code>; only used with libcurl:\n";

int main(int argc, char *argv[]){
  QApplication app(argc, argv);
  
  QStringList arglist = QCoreApplication::arguments();
  int arglist_length = arglist.size();

  int huh = arglist.indexOf("-h");
  if(huh < 0){
    huh = arglist.indexOf("--help");
  }
  if(huh > 0){
    char *hints = proxyhints();
    qDebug() << instructions;
    qDebug() << hints;
    free(hints);
    exit (0);
  }

  Rendezvous rendezvous;

  //parse the arguments the old fashioned way
  //server
  int server = arglist.indexOf("-s");
  if(server < 0){
    server = arglist.indexOf("--server");
  }
  if(server >= 0){
    if(server + 1 < arglist_length){
      rendezvous.setServer(arglist.at(server + 1));
    } else {
      qDebug() << " -s --server needs an argument!";
      exit (0);
    }
  }
  //proxy
  int proxy = arglist.indexOf("-p");
  if(proxy < 0){
    proxy = arglist.indexOf("--proxy");
  }
  if(proxy >= 0){
    if(proxy + 1 < arglist_length){
      rendezvous.setProxy(arglist.at(proxy + 1));
    } else {
      qDebug() << " -p --proxy needs an argument!";
      exit (0);
    }
  }
  //proxytype
  int proxytype = arglist.indexOf("-t");
  if(proxytype < 0){
    proxytype = arglist.indexOf("--proxytype");
  }
  if(proxytype >= 0){
    if(proxytype + 1 < arglist_length){
      rendezvous.setProxyType(arglist.at(proxytype + 1));
    } else {
      qDebug() << " -t --proxytype needs an argument!";
      exit (0);
    }
  }
  //geometry
  int geometry = arglist.indexOf("-g");
  if(geometry < 0){
    geometry = arglist.indexOf("--geometry");
  }
  if(geometry >= 0){
    if(geometry + 1 < arglist_length){
      rendezvous.setGeometry(arglist.at(geometry + 1));
    } else {
      qDebug() << " -g --geometry needs an argument!";
      exit (0);
    }
  }
  //curl
  int curl = arglist.indexOf("-c");
  if(curl < 0){
    curl = arglist.indexOf("--curl");
  }
  if((curl >= 0) && (curl < arglist_length)){
    rendezvous.setUseCurl(true);
  }
  //ssl
  int ssl = arglist.indexOf("-l");
  if(ssl < 0){
    ssl = arglist.indexOf("--ssl");
  }
  if((ssl >= 0) && (ssl < arglist_length)){
    rendezvous.setSecure(true);
  }
  //dancing
  int nodancing = arglist.indexOf("-n");
  if(nodancing < 0){
    nodancing = arglist.indexOf("--no-dancing");
  }
  if((nodancing >= 0) && (nodancing < arglist_length)){
    rendezvous.setNoDancing();
  }
  //debug
  int debug = arglist.indexOf("-d");
  if(debug < 0){
    debug = arglist.indexOf("--debug");
  }
  if((debug >= 0) && (debug < arglist_length)){
    Stegospawner::debug = true;
  }
  
  //Dancer *dancer = new Dancer("");
  //dancer->start();

  //bool retval = Stegospawner::spawnStegotorus("127.0.0.1", "8081", "127.0.0.1:1080");
  //  fprintf(stderr, "spawnStegotorus returned %d\n", retval);
  

  // FYI just in case we want to include other executables (like stego etc) ...
  //#include <mach-o/dyld.h>
  //char path[1024];
  //uint32_t size = sizeof(path);
  //if (_NSGetExecutablePath(path, &size) == 0)
  //  fprintf(stderr, "executable path is %s\n", path);
  //else
  //  fprintf(stderr, "buffer too small; need size %u\n", size);
  
  return app.exec();
}
