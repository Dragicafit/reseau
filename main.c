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

voisin* voisins[VOISINS_SIZE] = {NULL};
donnee* donnees[DONNEES_SIZE] = {NULL};

int main(int argc, char const* argv[]) {
  int s, val = 1, rc;
  uint8_t req[PAQUET_SIZE] = {0};

  paquet* p = malloc(sizeof(paquet) + sizeof(tlv*));
  memset(p, 0, sizeof(paquet) + sizeof(tlv*));
  p->magic = 95;
  p->version = 1;
  p->length = sizeof(tlv*);
  tlv* t = malloc(sizeof(tlv));
  memset(t, 0, sizeof(tlv));
  p->body[0] = t;
  t->type = 2;

  uint8_t* reply = arcParser(p);

  memset(p, 0, sizeof(paquet) + sizeof(tlv*));
  p->magic = 95;
  p->version = 1;
  p->length = sizeof(tlv*);
  tlv* t2 = malloc(sizeof(tlv) + 16);
  memset(t, 0, sizeof(tlv) + 16);
  p->body[0] = t;
  t->type = 4;
  t->network_hash = networkHash(donnees);

  uint8_t* reply4 = arcParser(p);

  struct sockaddr_in6 addr, client, serv;
  socklen_t serv_len = sizeof(serv);

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

  close(s);
  return 0;
}
