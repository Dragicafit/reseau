#define _GNU_SOURCE
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

paquet* parser(char* req1) {
  char req[] = {95, 1,  1,  0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
                26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
                41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
                56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
                71, 72, 73, 74, 75, 76, 77, 78, 79, 80};
  paquet p;
  memcpy(&p, req, sizeof(paquet));

  tlv list[NB_TLV_MAX];
  int count = 0;
  for (int i = 0; i < p.body_length;) {
    if (req[i] == 0) {
      i++;
      continue;
    }
    if (req[i + 1] + i > p.body_length) return NULL;
    tlv t;
    if (req[i] >= 3 && req[i] <= 9) {
      t.type = req[i];
      t.length = req[i + 1];
    }

    switch (req[i]) {
      case 1:
        i += 2;
        for (int j = 0; j < req[i - 1]; j++) {
          if (req[i + j] != 0) return NULL;
        }
        i += req[i - 1];
        break;
      case 2:
        if (req[i + 1] != 0) return NULL;
        tlv t = {.type = req[i]};
        list[count++] = t;
        i += 2;
        break;
      case 3:
        i += 2;
        memcpy(t.address.ip, &req[i], 16);
        i += 16;
        memcpy(t.address.port, &req[i], 2);
        list[count++] = t;
        i += 2;
        break;
      case 4:
        i += 2;
        memcpy(t.network_hash, &req[i + 2], 16);
        list[count++] = t;
        i += 16;
      case 5:
        i += 2;
        if (req[i + 1] != 0) return NULL;
        list[count++] = t;
        break;
      case 6:
        i += 2;
        memcpy(t.data.id, &req[i], 4);
        i += 4;
        memcpy(t.data.seqno, &req[i], 2);
        i += 2;
        memcpy(t.node_hash, &req[i], 16);
        list[count++] = t;
        i += 16;
        break;
      case 7:
        i += 2;
        memcpy(t.data.id, &req[i], 4);
        list[count++] = t;
        i += 4;
        break;
      case 8:
        i += 2;
        memcpy(t.data.id, &req[i], 4);
        i += 4;
        memcpy(t.data.seqno, &req[i], 2);
        i += 2;
        memcpy(t.node_hash, &req[i], 16);
        i += 16;
        int data_size = t.length - 22;
        if (data_size > 192) return NULL;
        memcpy(t.data.data, &req[i], data_size);
        list[count++] = t;
        break;
      case 9:
        i += 2;
        memcpy(t.data.data, &req[i + 2], req[i + 1]);
        list[count++] = t;
        i += req[i + 1];
        break;
      default:
        return NULL;
    }
  }

  printf("%hu\n%hu\n%hu\n%hu\n%hu\n%hu\n%hu\n%hu\n%hu\n%hu\n%hu\n%hu\n%hu\n",
         p.magic, p.version, p.body_length, p.body[0].type, p.body[0].length,
         (char)p.body[0].address.ip, (char)p.body[0].network_hash,
         (char)p.body[0].node_hash, (char)p.body[0].data.id, p.body[1].type,
         p.body[1].length, (char)p.body[1].network_hash,
         (char)p.body[1].node_hash);
  paquet* paq = malloc(sizeof(paquet) + sizeof(list));
  memcpy(paq, p, sizeof(p));
  paq->body_length = sizeof(list);
  memcpy(paq->body, &list, sizeof(list));
  return paq;
}

int main() {
  parser(NULL);
  exit(EXIT_SUCCESS);
  int s, val = 1, rc;
  char req[PAQUET_SIZE];
  char* reply = "";
  struct sockaddr_in6 addr, client;
  socklen_t client_len = sizeof(client);

  if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) handle_error("socket error");
  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0)
    handle_error("sockop error");

  memset(&addr, 0, sizeof(addr));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(3000);

  if ((rc = bind(s, (struct sockaddr*)&addr, sizeof(addr))) < 0)
    handle_error("bind error");

  while (1) {
    rc = recvfrom(s, req, sizeof(req), 0, &client, &client_len);
    if (rc < 0) continue;

    rc = sendto(s, reply, strlen(reply), 0, &client, client_len);
    if (rc < 0) fprintf(stderr, "send error");
  }

  close(s);
  return 0;
}
