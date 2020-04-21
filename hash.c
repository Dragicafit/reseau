#include "hash.h"

#include <openssl/sha.h>
#include <string.h>
#include <unistd.h>

#include "constantes.h"
#include "modele.h"

__uint128_t nodeHash(donnee* donnee) {
  __uint128_t h;
  char concDonnee[8 + 2 + DATA_SIZE] = "";
  char strId[9];
  memcpy(strId, &donnee->id, 8);
  strId[8] = '\0';
  strcat(concDonnee, strId);
  memcpy(strId, &donnee->seqno, 2);
  strId[2] = '\0';
  strcat(concDonnee, strId);
  strcat(concDonnee, donnee->data);
  SHA256((uint8_t*)concDonnee, strlen(concDonnee), (uint8_t*)&h);
  return h;
}

__uint128_t networkHash(donnee* donnees[]) {
  __uint128_t h;
  __uint128_t concDonnee[sizeof(__uint128_t) * DONNEES_SIZE] = {0};
  int count = 0;
  for (int i = 0; i < DONNEES_SIZE; i++) {
    donnee* d = donnees[i];
    if (d == NULL) continue;
    __uint128_t h1 = nodeHash(d);
    concDonnee[count++] = h1;
  }
  SHA256((uint8_t*)concDonnee, count, (uint8_t*)&h);
  return h;
}
