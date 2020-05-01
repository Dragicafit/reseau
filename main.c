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

#include "constantes.h"
#include "hash.h"
#include "modele.h"
#include "parser.h"
#include "tlv.h"

uint64_t id;
voisin* voisins[VOISINS_SIZE] = {NULL};
donnee* donnees[DONNEES_SIZE] = {NULL};
int nbVoisins = 0;
int nbDonnees = 0;

int main(int argc, char const* argv[]) {
  srand(time(NULL));
  id = random_id();
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
  if (inet_pton(AF_INET6,
                ipv6 ? "2001:660:3301:9200::51c2:1b9b" : "::ffff:81.194.27.155",
                &serv.sin6_addr) < 1)
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
        envoi = arcParser(creerPaquetTlv4(donnees, nbDonnees));
        rc = sendto(s, envoi, ntohs(*(uint16_t*)&envoi[2]) + 4, 0,
                    addrToSockaddr(&v->s), sizeof(struct sockaddr_in6));
        if (rc < 0) handle_error("select error");
        write(0, "Envoi d'un TLV4 a un voisin\n", 28);

        if (voisins[i]->permanent) continue;

        if (voisins[i]->last_change + INTERVAL_70 <= time(NULL)) {
          free(voisins[i]);
          nbVoisins--;
          voisins[i] = voisins[nbVoisins];
        }
      }

      if (nbVoisins > MAX_SEND_TLV2) continue;
      voisin* v = voisins[rand() % nbVoisins];
      envoi = arcParser(creerPaquetTlv2());
      rc = sendto(s, envoi, ntohs(*(uint16_t*)&envoi[2]) + 4, 0,
                  addrToSockaddr(&v->s), sizeof(struct sockaddr_in6));
      if (rc < 0) handle_error("select error");
      write(0, "Envoi d'un TLV2 a un voisin aléatoire\n", 39);
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
      voisin* v;
      donnee* d = NULL;
      int position;
      switch (t->type) {
        case 2:
          v = voisins[rand() % nbVoisins];
          envoi = arcParser(creerPaquetTlv3(&v->s));
          sendto(s, envoi, ntohs(*(uint16_t*)&envoi[2]) + 4, 0,
                 addrToSockaddr(&v->s), sizeof(struct sockaddr_in6));
          write(0, "Envoi d'un tlv 3\n", 17);
          break;
        case 3:
          envoi = arcParser(creerPaquetTlv4(donnees, nbDonnees));
          sendto(s, envoi, ntohs(*(uint16_t*)&envoi[2]) + 4, 0,
                 addrToSockaddr(&t->address), sizeof(struct sockaddr_in6));
          write(0, "Envoi d'un tlv 4\n", 17);
          break;
        case 4:
          if (networkHash(donnees, nbDonnees) == t->network_hash) continue;
          envoi = arcParser(creerPaquetTlv5());
          sendto(s, envoi, ntohs(*(uint16_t*)&envoi[2]) + 4, 0,
                 (struct sockaddr*)&serv, serv_len);
          write(0, "Envoi d'un tlv 5\n", 17);
          break;
        case 5:
          envoi = arcParser(creerPaquetTlv6(donnees, nbDonnees));
          sendto(s, envoi, ntohs(*(uint16_t*)&envoi[2]) + 4, 0,
                 (struct sockaddr*)&serv, serv_len);
          write(0, "Envoi d'une liste de tlv 6\n", 27);
          break;
        case 6:
          for (int j = 0; j < nbDonnees; j++) {
            d = donnees[j];
            if (d->id != t->data->id) break;
          }
          if (d == NULL) continue;
          if (d->node_hash == t->data->node_hash) continue;
          envoi = arcParser(creerPaquetTlv7(t->data->id));
          sendto(s, envoi, ntohs(*(uint16_t*)&envoi[2]) + 4, 0,
                 (struct sockaddr*)&serv, serv_len);
          write(0, "Envoi d'un tlv 7\n", 17);
          break;
        case 7:
          for (int j = 0; j < nbDonnees; j++) {
            d = donnees[j];
            if (d->id == t->data->id) break;
          }
          if (d == NULL) continue;
          envoi = arcParser(creerPaquetTlv8(d));
          sendto(s, envoi, ntohs(*(uint16_t*)&envoi[2]) + 4, 0,
                 (struct sockaddr*)&serv, serv_len);
          write(0, "Envoi d'un tlv 8\n", 17);
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
