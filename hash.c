#include "hash.h"

#include <openssl/sha.h>
#include <unistd.h>

#include "modele.h"

uint8_t* networkHash() {
  uint8_t* h;

  return h;
}
uint8_t* nodeHash(donnee* donnee) {
  uint8_t* h;
  char* concDonnee = "";
  uint8_t strId[9];
  memcpy(strId, &donnee->id, 8);
  strId[8] = '\0';
  strcat(concDonnee, strId);
  memcpy(strId, &donnee->seqno, 2);
  strId[2] = '\0';
  strcat(concDonnee, strId);
  strcat(concDonnee, donnee->data);
  return h;
}