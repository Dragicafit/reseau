#ifndef PARSER
#define PARSER

#include <unistd.h>

#include "modele.h"

paquet* parser(uint8_t req[]);
uint8_t* arcParser(paquet* p);

#endif