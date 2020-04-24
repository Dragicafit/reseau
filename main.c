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
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "constantes.h"
#include "hash.h"
#include "modele.h"
#include "parser.h"
#include "tlv.h"

voisin* voisins[VOISINS_SIZE] = {NULL};
donnee* donnees[DONNEES_SIZE] = {NULL};
int nbVoisins = 0;
int nbDonnees = 0;

int main(int argc, char const* argv[]) {
  srand(time(NULL));

  int s, val = 1, rc;
  uint8_t req[PAQUET_SIZE] = {0};
  int* pointerNbVoisins = &nbVoisins;
  uint8_t* envoi;

  paquet* p = creerPaquetTlv2();

  uint8_t* reply = arcParser(p);

  uint8_t* reply4 = arcParser(p);

  struct sockaddr_in6 addr, client, serv;
  socklen_t serv_len = sizeof(serv);
  socklen_t client_len = sizeof(client);

  char ipv6 = 0;
  if (argc > 1 && argv[1][0] == '1') {
    ipv6 = 1;
  }

  if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) handle_error("socket error");
  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0)
    handle_error("sockop error");

  memset(&addr, 0, sizeof(addr));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(3001);

  if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    handle_error("bind s error");

  memset(&serv, 0, sizeof(serv));
  serv.sin6_family = AF_INET6;
  serv.sin6_port = htons(1212);
  if (inet_pton(AF_INET6,
                ipv6 ? "2001:660:3301:9200::51c2:1b9b" : "::ffff:81.194.27.155",
                &serv.sin6_addr) < 1)
    handle_error("inet error");

  parser(reply);

  rc = sendto(s, reply, (reply[2] << 8) + reply[3] + 4, 0,
              (struct sockaddr*)&serv, serv_len);
  if (rc < 0) handle_error("sendto error");

  rc = recvfrom(s, req, PAQUET_SIZE, 0, (struct sockaddr*)&serv, &serv_len);
  if (rc < 0) handle_error("recvf error");

  p = parser(req);

  memset(&client, 0, sizeof(client));
  client.sin6_family = AF_INET6;
  client.sin6_port = p->body[0]->address.port;
  client.sin6_addr = p->body[0]->address.ip;

  memset(req, 0, PAQUET_SIZE);
  parser(reply4);

  rc = sendto(s, reply4, (reply4[2] << 8) + reply4[3] + 4, 0,
              (struct sockaddr*)&client, sizeof(client));
  if (rc < 0) handle_error("sendto error");

  rc = recvfrom(s, req, PAQUET_SIZE, 0, (struct sockaddr*)&serv, &serv_len);
  if (rc < 0) handle_error("recvf error");

  parser(req);

  // debut

  rc = recvfrom(s, req, PAQUET_SIZE, 0, (struct sockaddr*)&client, &client_len);
  if (rc < 0) handle_error("recvf error");

  p = parser(req);
  if (p == NULL) return -1;

  char present = 0;
  for (int i = 0; i < VOISINS_SIZE; i++) {
    if (sock_addr_cmp_addr(&voisins[i]->s, &client)) present = 1;
  }

  if (!present) {
    if (nbVoisins >= MAX_VOISINS) return -1;
    voisins[nbVoisins] = calloc(1, sizeof(voisin));
    voisins[nbVoisins]->permanent = 0;
    memcpy(&voisins[nbVoisins]->s.ip, &client.sin6_addr,
           sizeof(struct in6_addr));
    voisins[nbVoisins]->s.port = client.sin6_port;
    nbVoisins++;
  }

  voisins[nbVoisins]->last_change = time(NULL);

  time_t tempsDebut = time(NULL);

  while (1) {
    if (tempsDebut + 20 <= time(NULL)) {
      for (int i = 0; i < *pointerNbVoisins; i++) {
        voisin* v = voisins[i];
        envoi = arcParser(creerPaquetTlv4(donnees));
        sendto(s, envoi, (envoi[2] << 8) + envoi[3] + 4, 0,
               addrToSockaddr(&v->s), sizeof(struct sockaddr_in6));
        if (voisins[i]->permanent) continue;
        if (voisins[i]->last_change + 70 <= time(NULL)) {
          free(voisins[i]);
          *pointerNbVoisins--;
          voisins[i] = voisins[nbVoisins];
        }
      }

      if (nbVoisins > 5) continue;

      voisin* v = voisins[rand() % nbVoisins];
      envoi = arcParser(creerPaquetTlv2());
      sendto(s, envoi, (envoi[2] << 8) + envoi[3] + 4, 0, addrToSockaddr(&v->s),
             sizeof(struct sockaddr_in6));
      tempsDebut = time(NULL);
    }

    fd_set set;
    struct timeval timeout;
    FD_ZERO(&set);
    FD_SET(s, &set);
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    int rv = select(s + 1, &set, NULL, NULL, &timeout);
    if (rv < 1) continue;

    recvfrom(s, req, PAQUET_SIZE, 0, (struct sockaddr*)&serv, &serv_len);
    p = parser(req);
    if (p == NULL) continue;

    for (int i = 0; i < p->length / sizeof(tlv); i++) {
      tlv* t = p->body[i];
      voisin* v;
      switch (t->type) {
        case 2:
          v = voisins[rand() % nbVoisins];
          envoi = arcParser(creerPaquetTlv3(&v->s));
          sendto(s, envoi, (envoi[2] << 8) + envoi[3] + 4, 0,
                 addrToSockaddr(&v->s), sizeof(struct sockaddr_in6));
          break;
        case 3:
          envoi = arcParser(creerPaquetTlv4(donnees));
          sendto(s, envoi, (envoi[2] << 8) + envoi[3] + 4, 0,
                 addrToSockaddr(&t->address), sizeof(struct sockaddr_in6));
          break;
        case 4:
          if (networkHash(donnees) == t->network_hash) continue;
          envoi = arcParser(creerPaquetTlv5());
          sendto(s, envoi, (envoi[2] << 8) + envoi[3] + 4, 0,
                 (struct sockaddr*)&serv, serv_len);
          break;
        case 5:
          envoi = arcParser(creerPaquetTlv6(donnees, nbDonnees));
          sendto(s, envoi, (envoi[2] << 8) + envoi[3] + 4, 0,
                 (struct sockaddr*)&serv, serv_len);
          break;
        case 6:
          break;
        case 7:
          break;
        case 8:
          break;
        case 9:
          break;
        default:
          continue;
      }
    }
  }

  close(s);
  return 0;
}
