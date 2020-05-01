#ifndef TLV
#define TLV

#include "modele.h"

paquet* creerPaquetTlv2();
paquet* creerPaquetTlv3(addr* ad);
paquet* creerPaquetTlv4(donnee* donnees[], int nbDonnees);
paquet* creerPaquetTlv5();
paquet* creerPaquetTlv6(donnee* donnees[], int nbDonnees);
paquet* creerPaquetTlv7(uint64_t id);
paquet* creerPaquetTlv8(donnee* d);

#endif