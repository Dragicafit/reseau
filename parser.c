#define _GNU_SOURCE
#include "parser.h"

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
        t->data->data[data_size] = '\0';
        i += data_size;
        break;
      case 9:
        data_size = t->length;
        t->data = malloc(sizeof(donnee) + data_size + 1);
        memcpy(t->data->data, &req[i], data_size);
        t->data->data[data_size] = '\0';
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

uint8_t* arcParser(paquet* p) {
  if (0) {
    paquet* p1 = malloc(PAQUET_SIZE);
    p1->magic = 95;
    p1->version = 1;
    p1->body_length = 0;
    p1->length = 0;
    tlv* t = malloc(sizeof(tlv) + DATA_SIZE);
    p1->body[0] = t;
    t->type = 2;
    t->length = 0;
    p = p1;
  }
  int data_size;

  uint8_t* req = malloc(4 + p->body_length);
  memset(req, 0, sizeof(req));
  req[0] = p->magic;
  req[1] = p->version;
  *((uint16_t*)&req[2]) = htobe16(p->body_length);

  if (req[0] != 95) return NULL;
  if (req[1] != 1) return NULL;
  if (sizeof(req) > PAQUET_SIZE) return NULL;

  int count = 4;
  for (int i = 0; i < p->length; i++) {
    tlv* t = p->body[i];
    if (t == NULL) return NULL;
    if (t->type == 0) return NULL;
    req[count++] = t->type;
    req[count++] = t->length;
    if (count + t->length - 1 > sizeof(req)) return NULL;
    switch (t->type) {
      case 1:
        for (int j = 0; j < t->length; j++) {
          req[count++] = 0;
        }
        break;
      case 2:
        if (t->length != 0) return NULL;
        break;
      case 3:
        memcpy(&req[count], &t->address.ip, 16);
        count += 16;
        memcpy(&req[count], &t->address.port, 2);
        count += 2;
        break;
      case 4:
        memcpy(&req[count], &t->network_hash, 16);
        count += 16;
        break;
      case 5:
        if (t->length != 0) return NULL;
        break;
      case 6:
        memcpy(&req[count], &t->data->id, 8);
        count += 8;
        memcpy(&req[count], &t->data->seqno, 2);
        count += 2;
        memcpy(&req[count], &t->node_hash, 16);
        count += 16;
        break;
      case 7:
        memcpy(&req[count], &t->data->id, 8);
        count += 8;
        break;
      case 8:
        data_size = t->length - 26;
        if (data_size > DATA_SIZE) return NULL;
        memcpy(&req[count], &t->data->id, 8);
        count += 8;
        memcpy(&req[count], &t->data->seqno, 2);
        count += 2;
        memcpy(&req[count], &t->node_hash, 16);
        count += 16;
        memcpy(&req[i], t->data->data, data_size);
        count += data_size;
        break;
      case 9:
        data_size = t->length;
        memcpy(&req[i], t->data->data, data_size);
        count += data_size;
        break;
      default:
        count += t->length;
        continue;
    }
  }

  return req;
}
