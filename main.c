#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "constantes.h"
#include "modele.h"

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
        printf("network hash : \t\t%x%x\n", ((uint64_t*)&t->network_hash)[0],
               ((uint64_t*)&t->network_hash)[1]);
        break;
      case 6:
        printf("id : \t\t\t%lu\n", t->data->id);
        printf("seqno : \t\t\t%hu\n", t->data->seqno);
        printf("node hash : \t\t%x%x\n", ((uint64_t*)&t->node_hash)[0],
               ((uint64_t*)&t->node_hash)[1]);
        break;
      case 7:
        printf("id : \t\t\t%lu\n", t->data->id);
        break;
      case 8:
        printf("id : \t\t\t%lu\n", t->data->id);
        printf("seqno : \t\t\t%hu\n", t->data->seqno);
        printf("node hash : \t\t%x%x\n", ((uint64_t*)&t->node_hash)[0],
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
  int data_size;

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
        t->data = malloc(sizeof(donnee));
        bigIndia(i, req, t->data->id, 8);
        bigIndia(i, req, t->data->seqno, 2);
        bigIndia(i, req, t->node_hash, 16);
        break;
      case 7:
        t->data = malloc(sizeof(donnee));
        bigIndia(i, req, t->data->id, 8);
        break;
      case 8:
        data_size = t->length - 26;
        if (data_size > DATA_SIZE) return NULL;
        t->data = malloc(sizeof(donnee) + data_size + 1);
        bigIndia(i, req, t->data->id, 8);
        bigIndia(i, req, t->data->seqno, 2);
        bigIndia(i, req, t->node_hash, 16);
        memcpy(t->data->data, &req[i], data_size);
        t->data->data[data_size + 1] = '\0';
        i += data_size;
        break;
      case 9:
        data_size = t->length;
        t->data = malloc(sizeof(donnee) + data_size + 1);
        memcpy(t->data->data, &req[i], data_size);
        t->data->data[data_size + 1] = '\0';
        i += data_size;
        break;
      default:
        i += t->length;
        continue;
    }
    list[count++] = t;
  }

  p = realloc(p, sizeof(paquet) + sizeof(tlv*) * count);
  p->length = count;
  for (int i = 0; i < p->length; i++) {
    p->body[i] = list[i];
  }

  printPaquet(p);

  return p;
}

int main(int argc, char const* argv[]) {
  int s, val = 1, rc;
  uint8_t req[PAQUET_SIZE] = {0};
  char reply[] = {95, 1, 0, 2, 2, 0};
  char reply4[] = {95, 1, 0, 18, 4, 16, 0, 0, 0, 0, 0,
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
