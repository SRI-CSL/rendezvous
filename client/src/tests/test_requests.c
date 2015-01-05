#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "defiantclient.h"
#include "defiantrequest.h"
#include "platform.h"

char* bad[] = {
  "http://vm06.csl.sri.com",
  "http://vm06.csl.sri.com/probably/not/a/valid/path/to/picture.png?hash=",
  "http://vm06.csl.sri.com/probably/not/a/valid/path/to/picture.png?hash=AdWw0==",
  "http://vm06.csl.sri.com/probably/not/a/valid/path/to/picture.png?hash=AdWw0f2JZyGF8bIdoU6!@#$%^&*()_ABgdPeExsR6ZaFE8nogYrqDVYXLdhgck400Vu3DGh2GhZykxA6/jzk+oc6kckXdDTlcg2YAdAWT/UUuwEWDUiG62vL78evDLfnykdabOZNT2FRePA5LIcGY3UIwnZkBW93qTKPZPcrX7snaz5AXvnSCbocgTC//uL2iELGUOCA==",
  "http://vm06.csl.sri.com/probably/not/a/valid/path/to/picture.png?hash=AdWw0f2JZyGF8bIdoU6KiVRVdt8prPjna5+rB8Omj0D6tfynmlnPen0p5p+2zSYFetBavuvi+a9rgQTaEqH3o/y4BAuhyM75whKGYc8ux08x24F8bIhzA0JRRre2pRj6XdJYlPU0v4R3RkAxPg4OIw5hURzzpcGBbcK95jDd/2KqABgdPeExsR6ZaFE8nogYrqDVYXLdhgck400Vu3DGh2GhZykxA6/jzk+oc6kckXdDTlcg2YAdAWT/UUuwEWDUiG62vL78evDLfnykdabOZNT2FRePA5LIcGY3UIwnZkBW93qTKPZPcrX7snaz5AXvnSCbocgTC//uL2iELGUOCA1234567890==",
  "http://vm06.csl.sri.com/probably/not/a/valid/path/to/picture.png?hash=AdWw0f2JZyGF8bIdoU6KiVRVdt8prPjna5+rB8Omj0D6tfynmlnPen0p5p+2zSYFetBavuvi+a9rgQTaEqH3o/y4BAuhyM75whKGYc8ux08x24F8bIhzA0JRRre2pRj6XdJYlPU0v4R3RkAxPg4OIw5hURzzpcGBbcK95jDd/2KqABgdPeExsR6ZaFE8nogYrqDVYXLdhgck400Vu3DGh2GhZykxA6/jzk+oc6kckXdDTlcg2YAdAWT/UUuwEWDUiG62vL78evDLfnykdabOZNT2FRePA5LIcGY3UIwnZkBW93qTKPZPcrX7snaz5AXvnSCbocgTC//uL2iELGUOCA",
  "http://vm06.csl.sri.com/probably/not/a/valid/path/to/picture.png?hash=AdWw0f2JZyGF8bIdoU6KiVRVdt8prPjna5+rB8Omj0D6tfynmlnPen0p5p+2zSYFetBavuvi+a9rgQTaEqH3o/y4BAuhyM75whKGYc8ux08x24F8bIhzA0JRRre2pRj6XdJYlPU0v4R3RkAxPg4OIw5hURzzpcGBbcK95jDd/2KqABgdPeExsR6ZaFE8nogYrqDVYXLdhgck400Vu3DGh2GhZykxA6/jzk+oc6kckXdDTlcg2YAdAWT/UUuwEWDUiG62vL78evDLfnykdabOZNT2FRePA5LIcGY3UIwnZkBW93qTKPZPcrX7snaz5AXvnSCbocgTC//uL2iELGUOCA==D6tfynmlnPen0p5p+2zSYFetBavuvi+a9rgQTaEqH3o/y4BAuhyM75whKGYc8ux08x24F8bIhzA0JRRre2pRj6XdJYlPU0v4R3RkAxPg4OIw5hURzzpcGBbcK95jDd/2KqABgdPeExsR6ZaFE8nogYrqDVYXLdhgck400Vu3DGh2GhZykxA6/jzk+oc6kckXdDTlcg2YAdAWT/UUuwEWDUiG62vL78evDLfnykdabOZNT2FRePA5LIcGY3UIwnZkBW93qTKPZPcrX7snaz5AXvnSCbocgTC//uL2iELGUOCA==",
  "http://vm06.csl.sri.com/probably/not/a/valid/path/to/picture.png?hash=ZM9hvcZdpJZjrnh/wtfQ4mi2U+npPlszP7oHoN4grjQke0sZWFhpn/XC9Mw6soZGDxZTHdwB7+yJaM7FNixdysvOf72PVs7AvgJYf14gNqp/pIG6zdOD0grFHF8WGl1qeca6jMz+uVu5/NxoIRWC02WovSJsbA5wG5VNYhMIE35PBafrXHRF9r/Bu/r9Wx6n58w5NXHnd/JyHsjocnUB5glGc0WUKbxcPUMJrY41I19z6gea07545EPq5/X+8v34nEzONO4sS9Iz6pWX/XSgHpaGT0Cz0R+7WeEFWJRdN2lBr3FiZMRzTGPjvLwohKOXqV6bd5jy7f7dhanhd8qvdg==",
  "http://vm06.csl.sri.com/probably/not/a/valid/path/to/picture.png?hash=ZM9hvcZdpJZjrnh/wtfQ4mi2U+npPlszP7oHoN4grjQke0sZWFhpn/XC9Mw6soZGDxZTHdwB7+yJaM7FNixdysvOf72PVs7AvgJYf14gNqp/pIG6zdOD0grFHF8WGl1qeca6jMz+uVu5/NxoIRWC02WovSJsbA5wG5VNYhMIE35PBafrXHRF9r/Bu/r9Wx6n58w5NXHnd/JyHsjocnUB5glGC0WUKbxcPUMJrY41I19z6gea07545EPq5/X+8v34nEzONO4sS9Iz6pWX/XSgHpaGT0Cz0R+7WeEFWJRdN2lBr3FiZMRzTGPjvLwohKOXqV6bd5jy7f7dhanhd8qvdg==",
  NULL
};





int main(int argc, char** argv){
  int errcode;
  int index = 0;
  char* url;
  char *keyfile = "../../data/vm06_private_key.bin";
  bf_key_pair_t* key_pair = NULL;
  FILE *fp = fopen(keyfile, "rb");
  if(fp == NULL){
    fprintf(stderr, "Couldn't open key-pair file, %s, go figure... \n", strerror(errno));
    exit(0);
  }
  errcode = bf_read_key_pair(fp, &key_pair);
  if(errcode != DEFIANT_OK){
    fprintf(stderr, "Couldn't load key pair from %s, errcode = %d, go figure... \n", keyfile, errcode);
    exit(0);
  }
  while((url = bad[index++]) != NULL){
    char* password = NULL;
    errcode = is_defiant_request(key_pair, url, &password);
    if(errcode == DEFIANT_OK){
      fprintf(stdout, "password = %s of length %" PRIsizet "\n", password, strlen(password));
    } else {
      fprintf(stdout, "errcode = %d\n", errcode);
    }
    free(password);
  }
  return 0;
}

