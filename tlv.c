#include "tlv.h"

#include <stdlib.h>

#include "constantes.h"
#include "hash.h"
#include "modele.h"

paquet* creerPaquetTlv2() {
  paquet* p = calloc(1, sizeof(paquet) + sizeof(tlv*));
  p->magic = 95;
  p->version = 1;
  p->length = sizeof(tlv*);
  tlv* t = calloc(1, sizeof(tlv));
  p->body[0] = t;
  t->type = 2;
  return p;
}

paquet* creerPaquetTlv3(addr* ad) {
  paquet* p = calloc(1, sizeof(paquet) + sizeof(tlv*));
  p->magic = 95;
  p->version = 1;
  p->length = sizeof(tlv*);
  tlv* t = calloc(1, sizeof(tlv));
  p->body[0] = t;
  t->type = 3;
  t->address = *ad;
  return p;
}

paquet* creerPaquetTlv4(donnee* donnees[], int nbDonnees) {
  paquet* p = calloc(1, sizeof(paquet) + sizeof(tlv*));
  p->magic = 95;
  p->version = 1;
  p->length = sizeof(tlv*);
  tlv* t = calloc(1, sizeof(tlv) + 16);
  p->body[0] = t;
  t->type = 4;
  t->network_hash = networkHash(donnees, nbDonnees);
  return p;
}

paquet* creerPaquetTlv5() {
  paquet* p = calloc(1, sizeof(paquet) + sizeof(tlv*));
  p->magic = 95;
  p->version = 1;
  p->length = sizeof(tlv*);
  tlv* t = calloc(1, sizeof(tlv));
  p->body[0] = t;
  t->type = 5;
  return p;
}

paquet* creerPaquetTlv6(donnee* donnees[], int nbDonnees) {
  paquet* p = calloc(1, sizeof(paquet) + sizeof(tlv*));
  p->magic = 95;
  p->version = 1;
  p->length = sizeof(tlv*) * nbDonnees;
  for (int i = 0; i < min(nbDonnees, 5); i++) {
    tlv* t = calloc(1, sizeof(tlv));
    p->body[i] = t;
    t->type = 6;
    t->data = donnees[i];
  }
  return p;
}

paquet* creerPaquetTlv7(uint64_t id) {
  paquet* p = calloc(1, sizeof(paquet) + sizeof(tlv*));
  p->magic = 95;
  p->version = 1;
  p->length = sizeof(tlv*);
  tlv* t = calloc(1, sizeof(tlv));
  p->body[0] = t;
  t->type = 7;
  t->data = calloc(1, sizeof(donnee));
  t->data->id = id;
  return p;
}

paquet* creerPaquetTlv8(donnee* d) {
  paquet* p = calloc(1, sizeof(paquet) + sizeof(tlv*));
  p->magic = 95;
  p->version = 1;
  p->length = sizeof(tlv*);
  tlv* t = calloc(1, sizeof(tlv));
  p->body[0] = t;
  t->type = 8;
  t->data = d;
  return p;
}