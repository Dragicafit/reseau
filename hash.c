#include "hash.h"

#include <openssl/sha.h>
#include <string.h>
#include <unistd.h>

#include "constantes.h"
#include "modele.h"

uint8_t* nodeHash(donnee* donnee) {
  uint8_t* h = NULL;
  char concDonnee[8 + 2 + DATA_SIZE] = "";
  char strId[9];
  memcpy(strId, &donnee->id, 8);
  strId[8] = '\0';
  strcat(concDonnee, strId);
  memcpy(strId, &donnee->seqno, 2);
  strId[2] = '\0';
  strcat(concDonnee, strId);
  strcat(concDonnee, donnee->data);
  SHA256((uint8_t*)concDonnee, strlen(concDonnee), h);
  return h;
}

uint8_t* networkHash() {
  uint8_t* h = NULL;

  return h;
}