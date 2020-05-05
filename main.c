#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "affichage.h"
#include "constantes.h"
#include "hash.h"
#include "modele.h"
#include "parser.h"
#include "tlv.h"

uint64_t id = 0;
voisin* voisins[VOISINS_SIZE] = {NULL};
donnee* donnees[DONNEES_SIZE] = {NULL};
int nbVoisins = 0;
int nbDonnees = 0;

int main(int argc, char const* argv[]) {
  srand(time(NULL));

  FILE* f = fopen("id.txt", "r+");
  if (f == NULL) {
    f = fopen("id.txt", "w+");
    if (f == NULL) {
      handle_error("Impossible de créer le fichier");
    }
  }

  fscanf(f, "%lu", &id);

  if (id == 0) {
    id = random_id();
    fprintf(f, "%lu", id);
  }
  fclose(f);

  write(0, "\n", 1);

  printf("id : %lu\n", id);

  int s, val = 1, rc;
  paquet* p;
  uint8_t req[PAQUET_SIZE] = {0};
  uint8_t* envoi;

  struct sockaddr_in6 addr, client, serv;
  socklen_t addr_len = sizeof(struct sockaddr_in6);
  socklen_t serv_len = sizeof(struct sockaddr_in6);
  socklen_t client_len = sizeof(struct sockaddr_in6);

  char ipv6 = 0;
  if (argc > 1 && argv[1][0] == '1') {
    ipv6 = 1;
  }

  if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) handle_error("socket error");
  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0)
    handle_error("sockop error");

  memset(&addr, 0, addr_len);
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(PORT);

  if (bind(s, (struct sockaddr*)&addr, addr_len) < 0)
    handle_error("bind s error");

  write(0, "Ouverture du serveur sur le port 3001\n", 38);

  memset(&serv, 0, serv_len);
  serv.sin6_family = AF_INET6;
  serv.sin6_port = htons(1212);
  if (inet_pton(AF_INET6, IPV4_TEST, &serv.sin6_addr) < 1)
    handle_error("inet error");

  voisins[0] = calloc(1, sizeof(voisin));
  voisins[0]->permanent = 1;
  memcpy(&voisins[0]->s.ip, &serv.sin6_addr, sizeof(struct in6_addr));
  voisins[0]->s.port = serv.sin6_port;
  voisins[0]->last_change = time(NULL);
  nbVoisins++;

  write(0, "Ajout du serveur dans la liste des voisins\n", 43);

  time_t tempsDebut = time(NULL);
  while (1) {
    if (tempsDebut + INTERVAL_20 <= time(NULL)) {
      tempsDebut = time(NULL);
      for (int i = 0; i < nbVoisins; i++) {
        voisin* v = voisins[i];
        paquet* p = creerPaquetTlv4(donnees, nbDonnees);
        envoi = arcParser(p);
        rc = sendto(s, envoi, ntohs(*(uint16_t*)&envoi[2]) + 4, 0,
                    addrToSockaddr(&v->s), sizeof(struct sockaddr_in6));
        if (rc < 0) handle_error("select error");
        write(0, "Envoi d'un TLV4 a un voisin \n", 28);

        printPaquet(p);

        if (voisins[i]->permanent) continue;

        if (voisins[i]->last_change + INTERVAL_70 <= time(NULL)) {
          free(voisins[i]);
          nbVoisins--;
          voisins[i] = voisins[nbVoisins];
        }
      }

      if (nbVoisins > MAX_SEND_TLV2) continue;
      voisin* v = voisins[rand() % nbVoisins];
      paquet* p = creerPaquetTlv2();
      envoi = arcParser(p);
      rc = sendto(s, envoi, ntohs(*(uint16_t*)&envoi[2]) + 4, 0,
                  addrToSockaddr(&v->s), sizeof(struct sockaddr_in6));
      if (rc < 0) handle_error("select error");
      write(0, "Envoi d'un TLV2 a un voisin aléatoire\n", 39);

      printPaquet(p);
    }

    fd_set set;
    struct timeval timeout;
    FD_ZERO(&set);
    FD_SET(s, &set);
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    int rv = select(s + 1, &set, NULL, NULL, &timeout);
    if (rv < 1) continue;

    rc = recvfrom(s, req, PAQUET_SIZE, 0, (struct sockaddr*)&client,
                  &client_len);
    if (rc < 0) handle_error("recvf error");

    write(0, "Réception d'un paquet\n", 23);

    p = parser(req);
    if (p == NULL) continue;

    int present = -1;
    for (int i = 0; i < nbVoisins; i++) {
      if (sock_addr_cmp_addr(&voisins[i]->s, &client)) {
        present = i;
        break;
      }
    }
    printf("Vérification de la présence\n");

    if (present == -1) {
      if (nbVoisins >= MAX_VOISINS) continue;
      present = nbVoisins;
      voisins[present] = calloc(1, sizeof(voisin));
      voisins[present]->permanent = 0;
      memcpy(&voisins[present]->s.ip, &client.sin6_addr,
             sizeof(struct in6_addr));
      voisins[present]->s.port = client.sin6_port;
      nbVoisins++;
      printf("Voisin ajouté\n");
    }
    voisins[present]->last_change = time(NULL);

    for (int i = 0; i < p->length / sizeof(tlv*); i++) {
      printf("Gestion du tlv n°%d\n", i);
      tlv* t = p->body[i];
      paquet* p;
      voisin* v;
      donnee* d = NULL;
      int position;
      switch (t->type) {
        case 2:
          v = voisins[rand() % nbVoisins];
          p = creerPaquetTlv3(&v->s);
          envoi = arcParser(p);
          sendto(s, envoi, ntohs(*(uint16_t*)&envoi[2]) + 4, 0,
                 addrToSockaddr(&v->s), sizeof(struct sockaddr_in6));
          write(0, "Envoi d'un tlv 3\n", 17);
          printPaquet(p);
          break;
        case 3:
          p = creerPaquetTlv4(donnees, nbDonnees);
          envoi = arcParser(p);
          sendto(s, envoi, ntohs(*(uint16_t*)&envoi[2]) + 4, 0,
                 addrToSockaddr(&t->address), sizeof(struct sockaddr_in6));
          write(0, "Envoi d'un tlv 4\n", 17);
          printPaquet(p);
          break;
        case 4:
          if (networkHash(donnees, nbDonnees) == t->network_hash) continue;
          p = creerPaquetTlv5();
          envoi = arcParser(p);
          sendto(s, envoi, ntohs(*(uint16_t*)&envoi[2]) + 4, 0,
                 (struct sockaddr*)&client, client_len);
          write(0, "Envoi d'un tlv 5\n", 17);
          printPaquet(p);
          break;
        case 5:
          p = creerPaquetTlv6(donnees, nbDonnees);
          envoi = arcParser(p);
          sendto(s, envoi, ntohs(*(uint16_t*)&envoi[2]) + 4, 0,
                 (struct sockaddr*)&client, client_len);
          write(0, "Envoi d'une liste de tlv 6\n", 27);
          printPaquet(p);
          break;
        case 6:
          for (int j = 0; j < nbDonnees; j++) {
            d = donnees[j];
            if (d->id != t->data->id) break;
          }
          if (d == NULL) continue;
          if (d->node_hash == t->data->node_hash) continue;
          p = creerPaquetTlv7(t->data->id);
          envoi = arcParser(p);
          sendto(s, envoi, ntohs(*(uint16_t*)&envoi[2]) + 4, 0,
                 (struct sockaddr*)&client, client_len);
          write(0, "Envoi d'un tlv 7\n", 17);
          printPaquet(p);
          break;
        case 7:
          for (int j = 0; j < nbDonnees; j++) {
            d = donnees[j];
            if (d->id == t->data->id) break;
          }
          if (d == NULL) continue;
          p = creerPaquetTlv8(d);
          envoi = arcParser(p);
          sendto(s, envoi, ntohs(*(uint16_t*)&envoi[2]) + 4, 0,
                 (struct sockaddr*)&client, client_len);
          write(0, "Envoi d'un tlv 8\n", 17);
          printPaquet(p);
          break;
        case 8:
          for (int j = 0; j < nbDonnees; j++) {
            d = donnees[j];
            position = j;
            if (d->id == t->data->id) break;
          }
          if (t->data->id != id) {
            if (d == NULL) {
              if (nbDonnees >= DATA_SIZE) continue;
              donnees[nbDonnees++] = t->data;
              write(0, "Ajout d'un nouvelle donnée\n", 28);
              continue;
            }
          }

          if (d->node_hash == t->data->node_hash) continue;

          if (t->data->id == id) {
            if (less_or_equals(d->seqno, t->data->seqno)) {
              d->seqno = sum(t->data->seqno, 1);
              write(0, "Changement du seqno\n", 20);
            }
            continue;
          }

          if (!less_or_equals(t->data->seqno, d->seqno)) {
            free(d);
            donnees[position] = t->data;
            write(0, "Modification d'une donnée\n", 27);
          }
          break;
        case 9:
          printf("Warning : %s", t->data->data);
          break;
        default:
          write(0, "Type inconu\n", 12);
          continue;
      }
    }
  }

  close(s);
  return 0;
}
