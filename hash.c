#define _GNU_SOURCE

#include <endian.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "constantes.h"
#include "modele.h"

__uint128_t nodeHash(donnee* donnee) {
  __uint128_t h;
  uint8_t buff[32];

  char concDonnee[sizeof(uint64_t) + sizeof(uint16_t) + DATA_SIZE] = {0};
  *(uint64_t*)concDonnee = htobe64(donnee->id);
  *(uint16_t*)&concDonnee[8] = donnee->seqno;
  memcpy(&concDonnee[10], donnee->data, donnee->length);

  SHA256((uint8_t*)concDonnee,
         sizeof(uint64_t) + sizeof(uint16_t) + donnee->length, buff);

  ((uint64_t*)&h)[0] = be64toh(*(uint64_t*)buff);
  ((uint64_t*)&h)[1] = be64toh(*(uint64_t*)&buff[8]);

  return h;
}

void tri(donnee* donnees[], int posDonnee[], int first, int last) {
  int i, j, pivot, temp;

  if (first < last) {
    pivot = first;
    i = first;
    j = last;

    while (i < j) {
      while (donnees[posDonnee[i]] <= donnees[posDonnee[pivot]] && i < last)
        i++;
      while (donnees[posDonnee[j]] > donnees[posDonnee[pivot]]) j--;
      if (i < j) {
        temp = posDonnee[i];
        posDonnee[i] = posDonnee[j];
        posDonnee[j] = temp;
      }
    }

    temp = posDonnee[pivot];
    posDonnee[pivot] = posDonnee[j];
    posDonnee[j] = temp;
    tri(donnees, posDonnee, first, j - 1);
    tri(donnees, posDonnee, j + 1, last);
  }
}

__uint128_t networkHash(donnee* donnees[], int nbDonnees) {
  int* posDonnee = calloc(nbDonnees, sizeof(int));
  for (int i = 0; i < nbDonnees; i++) posDonnee[i] = i;
  tri(donnees, posDonnee, 0, nbDonnees - 1);

  __uint128_t h;
  __uint128_t concDonnee[sizeof(__uint128_t) * DONNEES_SIZE] = {0};
  int count = 0;
  for (int i = 0; i < nbDonnees; i++) {
    donnee* d = donnees[posDonnee[i]];
    if (d == NULL) continue;
    __uint128_t h1 = d->node_hash;
    concDonnee[count++] = h1;
  }
  SHA256((uint8_t*)concDonnee, count, (uint8_t*)&h);
  return h;
}
