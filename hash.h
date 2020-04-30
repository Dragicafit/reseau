#ifndef HASH
#define HASH

#include <unistd.h>

#include "modele.h"

__uint128_t nodeHash(donnee* donnee);
__uint128_t networkHash(donnee* donnees[], int nbDonnees);

#endif