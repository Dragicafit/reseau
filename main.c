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

void printPaquet(paquet* p) {
  printf("magic : \t\t%hhu\n", p->magic);
  printf("version : \t\t%hhu\n", p->version);
  printf("body_length : \t\t%hu\n", p->body_length);
  char ip[INET6_ADDRSTRLEN];

  for (int i = 0; i < p->length; i++) {
    tlv* t = p->body[i];
    if (t->type == 0) {
      i++;
      continue;
    }
    printf("type : \t\t\t%hhu\n", t->type);
    printf("length : \t\t%hhu\n", t->length);

    switch (t->type) {
      case 3:
        inet_ntop(AF_INET6, &t->address.ip, ip, INET6_ADDRSTRLEN);
        printf("ip : \t\t\t%s:%hu\n", ip, ntohs(t->address.port));
        break;
      case 4:
        printf("network hash : \t\t%lx%lx\n", ((uint64_t*)&t->network_hash)[0],
               ((uint64_t*)&t->network_hash)[1]);
        break;
      case 6:
        printf("id : \t\t\t%lu\n", t->data->id);
        printf("seqno : \t\t\t%hu\n", t->data->seqno);
        printf("node hash : \t\t%lx%lx\n", ((uint64_t*)&t->node_hash)[0],
               ((uint64_t*)&t->node_hash)[1]);
        break;
      case 7:
        printf("id : \t\t\t%lu\n", t->data->id);
        break;
      case 8:
        printf("id : \t\t\t%lu\n", t->data->id);
        printf("seqno : \t\t\t%hu\n", t->data->seqno);
        printf("node hash : \t\t%lx%lx\n", ((uint64_t*)&t->node_hash)[0],
               ((uint64_t*)&t->node_hash)[1]);
        printf("data : \t\t\t%s\n", t->data->data);
        break;
      case 9:
        printf("warning : \t\t%s\n", t->data->data);
        break;
      default:
        break;
    }
    printf("\n");
  }
  fflush(stdout);
}

int main(int argc, char const* argv[]) {
  int s, val = 1, rc;
  uint8_t req[PAQUET_SIZE] = {0};
  uint8_t reply[] = {95, 1, 0, 2, 2, 0};
  uint8_t reply4[] = {95, 1, 0, 18, 4, 16, 0, 0, 0, 0, 0,
                      0,  0, 0, 0,  0, 0,  0, 0, 0, 0, 0};
  struct sockaddr_in6 addr, client, serv;

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

  rc =
      sendto(s, reply, sizeof(reply), 0, (struct sockaddr*)&serv, sizeof(serv));
  if (rc < 0) handle_error("sendto error");

  rc = recv(s, req, PAQUET_SIZE, 0);
  if (rc < 0) handle_error("recvf error");

  paquet* p = parser(req);

  memset(&client, 0, sizeof(client));
  client.sin6_family = AF_INET6;
  client.sin6_port = p->body[0]->address.port;
  client.sin6_addr = p->body[0]->address.ip;

  memset(req, 0, PAQUET_SIZE);
  parser(reply4);
  rc = sendto(s, reply4, sizeof(reply4), 0, (struct sockaddr*)&client,
              sizeof(client));
  if (rc < 0) handle_error("sendto error");

  rc = recv(s, req, PAQUET_SIZE, 0);
  if (rc < 0) handle_error("recvf error");

  parser(arcParser(parser(req)));

  close(s);
  return 0;
}
