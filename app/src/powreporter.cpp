#include "powreporter.h"
#include "onionmanager.h"
#include "rendezvous.h"
#include "util.h"



long PowReporter::maxAttempts = 26 * 26 * 26 * 26 * 26 * 26;

int PowReporter::attempts2percent(){
    long current = manager->attempts;
    return ((current * 100)/maxAttempts);
}

void PowReporter::run(){
  int cycles = 0;
  int cyclesPerPrint = 5;
  while(!quit){
    int p = attempts2percent();
    //    emit progressUpdate(33 + ((66 * p)/100));
    emit progressUpdate(p);
    sleep(1);
    cycles++;
    if(cycles % cyclesPerPrint == 0){
      Util::debug() << " POW search: " << p << "percent" ;
    }
  }
}

void  PowReporter::workerFinished(){
  quit = true;
}
