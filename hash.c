#include "hash.h"

#include <openssl/sha.h>
#include <stdlib.h>
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
  int* posDonnee = malloc(sizeof(int) * nbDonnees);
  for (int i = 0; i < nbDonnees; i++) posDonnee[i] = i;
  tri(donnees, posDonnee, 0, nbDonnees);

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
