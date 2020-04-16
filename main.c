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

#define bigIndia(i, req, data, size)                                   \
  {                                                                    \
    data = 0;                                                          \
    for (int j = size - 1; j <= 0; j--) data += (req[i++] << (j * 8)); \
  }

void printPaquet(paquet* p) {
  char ip[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &p->body[0]->address.ip, ip, INET6_ADDRSTRLEN);
  printf("%hhu\n", p->magic);
  printf("%hhu\n", p->version);
  printf("%hu\n", p->body_length);
  printf("%hhu\n", p->body[0]->type);
  printf("%hhu\n", p->body[0]->length);
  printf("%s:", ip);
  printf("%hu\n", ntohs(p->body[0]->address.port));
  printf("%lu, ", ((uint64_t*)&p->body[0]->network_hash)[0]);
  printf("%lu\n", ((uint64_t*)&p->body[0]->network_hash)[1]);
  printf("%lu, ", ((uint64_t*)&p->body[0]->node_hash)[0]);
  printf("%lu\n", ((uint64_t*)&p->body[0]->node_hash)[1]);
  printf("%lu\n", p->body[0]->data.id);
}

paquet* parser(uint8_t req[]) {
  if (0) {
    uint8_t req1[] = {
        95, 1,  1,  0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12,
        13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
        30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
        47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80};
    req = req1;
  }

  paquet* p = malloc(sizeof(paquet));
  memset(p, 0, sizeof(paquet));
  p->magic = req[0];
  p->version = req[1];
  p->body_length = (req[2] << 8) + req[3];

  if (p->magic != 95) return NULL;
  if (p->version != 1) return NULL;
  if (p->body_length + 4 > PAQUET_SIZE) return NULL;

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
          if (req[i++] != 0) return NULL;
        }
        break;
      case 2:
        if (t->length != 0) return NULL;
        break;
      case 3:
        memcpy(&t->address.ip, &req[i], 16);
        i += 16;
        t->address.port = htons((req[i++] << 8) + req[i++]);
        break;
      case 4:
        bigIndia(i, req, t->network_hash, 16);
        break;
      case 5:
        if (t->length != 0) return NULL;
        break;
      case 6:
        bigIndia(i, req, t->data.id, 4);
        bigIndia(i, req, t->data.seqno, 2);
        bigIndia(i, req, t->node_hash, 16);
        break;
      case 7:
        bigIndia(i, req, t->data.id, 4);
        break;
      case 8:
        bigIndia(i, req, t->data.id, 4);
        bigIndia(i, req, t->data.seqno, 2);
        bigIndia(i, req, t->node_hash, 16);
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

  printPaquet(p);

  return p;
}

int main() {
  int s, val = 1, rc;
  uint8_t req[PAQUET_SIZE] = {0};
  char reply[] = {95, 1, 0, 2, 2, 0};
  char reply4[] = {95, 1, 0, 18, 4, 16, 0, 0, 0, 0, 0,
                   0,  0, 0, 0,  0, 0,  0, 0, 0, 0, 0};
  struct sockaddr_in6 addr, client, serv;

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
  if (inet_pton(AF_INET6, "::ffff:81.194.27.155", &serv.sin6_addr) < 1)
    handle_error("inet error");

  parser(reply);

  rc = sendto(s, reply, sizeof(reply), 0, &serv, sizeof(serv));
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
  rc = sendto(s, reply4, sizeof(reply4), 0, &client, sizeof(client));
  if (rc < 0) handle_error("sendto error");

  rc = recv(s, req, PAQUET_SIZE, 0);
  if (rc < 0) handle_error("recvf error");

  for (int i = 0; i < 25; i++) {
    write(0, req[i], 8);
    write(0, req[i], 1);
  }

  parser(req);

  close(s);
  return 0;
}
