#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "modele.h"

#define handle_error(msg) \
  do {                    \
    perror(msg);          \
    exit(EXIT_FAILURE);   \
  } while (0)

#define PAQUET_SIZE 1024
#define NB_TLV_MAX PAQUET_SIZE - 4
#define DATA_SIZE 192

paquet* parser(char* req) {
  char req1[] = {95, 1,  1,  0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
                 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
                 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
                 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
                 71, 72, 73, 74, 75, 76, 77, 78, 79, 80};
  paquet* p = malloc(sizeof(paquet));
  memcpy(p, req, sizeof(paquet));

  if (p->magic != 95) return NULL;
  if (p->version != 1) return NULL;
  if (p->body_length > PAQUET_SIZE - 4) return NULL;

  tlv* list[NB_TLV_MAX];
  int count = 0;
  for (int i = 4; i < p->body_length + 4;) {
    if (req[i] == 0) {
      i++;
      continue;
    }
    tlv* t = malloc(sizeof(tlv));
    memset(t, 0, sizeof(tlv));
    t->type = req[i++];
    t->length = req[i++];
    if (i + t->length - 1 > p->body_length + 4) return NULL;

    switch (t->type) {
      case 1:
        for (int j = 0; j < t->length; j++) {
          if (req[i + j] != 0) return NULL;
        }
        i += t->length;
        break;
      case 2:
        if (t->length != 0) return NULL;
        break;
      case 3:
        memcpy(&t->address.ip, &req[i], 16);
        i += 16;
        memcpy(&t->address.port, &req[i], 2);
        i += 2;
        break;
      case 4:
        memcpy(&t->network_hash, &req[i], 16);
        i += 16;
        break;
      case 5:
        if (t->length != 0) return NULL;
        break;
      case 6:
        memcpy(&t->data.id, &req[i], 4);
        i += 4;
        memcpy(&t->data.seqno, &req[i], 2);
        i += 2;
        memcpy(&t->node_hash, &req[i], 16);
        i += 16;
        break;
      case 7:
        memcpy(&t->data.id, &req[i], 4);
        i += 4;
        break;
      case 8:
        memcpy(&t->data.id, &req[i], 4);
        i += 4;
        memcpy(&t->data.seqno, &req[i], 2);
        i += 2;
        memcpy(&t->node_hash, &req[i], 16);
        i += 16;
        int data_size = t->length - 22;
        if (data_size > DATA_SIZE) return NULL;
        memcpy(&t->data.data, &req[i], data_size);
        break;
      case 9:
        memcpy(&t->data.data, &req[i], t->length);
        i += t->length;
        break;
      default:
        i += t->length;
        continue;
    }
    list[count++] = t;
  }

  p = realloc(p, sizeof(paquet) + sizeof(tlv*) * count);
  for (int i = 0; i < count; i++) {
    p->body[i] = list[i];
  }

  printf("%hu\n%hu\n%u\n%hu\n%hu\n%hu\n%hu\n%hu\n%hu\n", p->magic, p->version,
         p->body_length, p->body[0]->type, p->body[0]->length,
         (char)p->body[0]->address.ip, (char)p->body[0]->network_hash,
         (char)p->body[0]->node_hash, (char)p->body[0]->data.id);

  return p;
}

int main() {
  int s, val = 1, rc;
  char req[PAQUET_SIZE];
  char reply[] = {95, 1, 2, 0, 2, 0};
  struct sockaddr_in6 addr, client, serv;
  socklen_t client_len = sizeof(client);

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
  serv.sin6_port = htons(8080);
  if (inet_pton(AF_INET6, "2001:660:3301:9200::51c2:1b9b", &serv.sin6_addr) < 1)
    handle_error("inet error");

  rc = sendto(s, reply, strlen(reply), 0, &serv, sizeof(serv));
  if (rc < 0) handle_error("sendto error");

  rc = recv(s, req, sizeof(req), 0);
  if (rc < 0) handle_error("recvfrom error");

  for (int i = 0; i < strlen(req); i++) {
    printf("%hhu\n", req[i]);
  }

  parser(req);

  while (1) {
    rc = recvfrom(s, req, sizeof(req), 0, &client, &client_len);
    if (rc < 0) continue;

    rc = sendto(s, reply, strlen(reply), 0, &client, client_len);
    if (rc < 0) fprintf(stderr, "send error");
  }

  close(s);
  return 0;
}
