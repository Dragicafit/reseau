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

#include "affichage.h"
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
  uint16_t body_length;
  uint8_t tlv_length;

  paquet* p = malloc(sizeof(paquet));
  memset(p, 0, sizeof(paquet));
  p->magic = req[0];
  p->version = req[1];
  body_length = (req[2] << 8) + req[3];

  if (p->magic != 95) return NULL;
  if (p->version != 1) return NULL;
  if (body_length + 4 > PAQUET_SIZE) return NULL;

  tlv* list[NB_TLV_MAX];
  int count = 0;
  for (int i = 4; i < body_length + 4;) {
    if (req[i] == 0) {
      i++;
      continue;
    }
    tlv* t = malloc(sizeof(tlv));
    memset(t, 0, sizeof(tlv));
    t->type = req[i++];
    tlv_length = req[i++];
    if (i + tlv_length - 1 > body_length + 4) return NULL;
    switch (t->type) {
      case 1:
        for (int j = 0; j < tlv_length; j++) {
          if (req[i++] != 0) return NULL;
        }
        break;
      case 2:
        if (tlv_length != 0) return NULL;
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
        if (tlv_length != 0) return NULL;
        break;
      case 6:
        t->data = malloc(sizeof(donnee));
        bigIndia(i, req, t->data->id, 8);
        bigIndia(i, req, t->data->seqno, 2);
        bigIndia(i, req, t->data->node_hash, 16);
        break;
      case 7:
        t->data = malloc(sizeof(donnee));
        bigIndia(i, req, t->data->id, 8);
        break;
      case 8:
        data_size = tlv_length - 26;
        if (data_size > DATA_SIZE) return NULL;
        t->data = malloc(sizeof(donnee) + data_size + 1);
        bigIndia(i, req, t->data->id, 8);
        bigIndia(i, req, t->data->seqno, 2);
        bigIndia(i, req, t->data->node_hash, 16);
        memcpy(t->data->data, &req[i], data_size);
        t->data->data[data_size] = '\0';
        t->data->length = data_size;
        i += data_size;
        break;
      case 9:
        data_size = tlv_length;
        t->data = malloc(sizeof(donnee) + data_size + 1);
        memcpy(t->data->data, &req[i], data_size);
        t->data->data[data_size] = '\0';
        t->data->length = data_size;
        i += data_size;
        break;
      default:
        i += tlv_length;
        continue;
    }
    list[count++] = t;
  }

  p = realloc(p, sizeof(paquet) + sizeof(tlv*) * count);
  p->length = count * sizeof(tlv*);
  for (int i = 0; i < p->length / sizeof(tlv*); i++) {
    p->body[i] = list[i];
  }

  printPaquet(p);

  return p;
}

uint8_t* arcParser(paquet* p) {
  if (0) {
    paquet* p1 = malloc(PAQUET_SIZE);
    memset(p, 0, PAQUET_SIZE);
    p1->magic = 95;
    p1->version = 1;
    p1->length = 0;
    tlv* t = malloc(sizeof(tlv) + DATA_SIZE);
    memset(t, 0, sizeof(tlv) + DATA_SIZE);
    p1->body[0] = t;
    t->type = 2;
    p = p1;
  }
  int data_size = 0;
  uint16_t paquet_size = 0;
  uint8_t tlv_body[DATA_SIZE + 26];

  uint8_t tlvList[PAQUET_SIZE - 4];

  for (int i = 0; i < p->length / sizeof(tlv*); i++) {
    int count = 0;
    tlv* t = p->body[i];
    if (t == NULL) return NULL;
    if (t->type == 0) return NULL;
    switch (t->type) {
      case 1:
        for (int j = 0; j < t->data->length; j++) {
          tlv_body[count++] = 0;
        }
        break;
      case 2:
        break;
      case 3:
        memcpy(&tlv_body[count], &t->address.ip, 16);
        count += 16;
        memcpy(&tlv_body[count], &t->address.port, 2);
        count += 2;
        break;
      case 4:
        memcpy(&tlv_body[count], &t->network_hash, 16);
        count += 16;
        break;
      case 5:
        break;
      case 6:
        memcpy(&tlv_body[count], &t->data->id, 8);
        count += 8;
        memcpy(&tlv_body[count], &t->data->seqno, 2);
        count += 2;
        memcpy(&tlv_body[count], &t->data->node_hash, 16);
        count += 16;
        break;
      case 7:
        memcpy(&tlv_body[count], &t->data->id, 8);
        count += 8;
        break;
      case 8:
        data_size = t->data->length;
        if (data_size > DATA_SIZE) return NULL;
        memcpy(&tlv_body[count], &t->data->id, 8);
        count += 8;
        memcpy(&tlv_body[count], &t->data->seqno, 2);
        count += 2;
        memcpy(&tlv_body[count], &t->data->node_hash, 16);
        count += 16;
        memcpy(&tlv_body[count], t->data->data, data_size);
        count += data_size;
        break;
      case 9:
        data_size = t->data->length;
        memcpy(&tlv_body[count], t->data->data, data_size);
        count += data_size;
        break;
      default:
        continue;
    }
    tlvList[paquet_size++] = t->type;
    tlvList[paquet_size++] = count;
    memcpy(&tlvList[paquet_size], tlv_body, count);
    paquet_size += count;
  }

  uint8_t* req = malloc(4 + paquet_size);
  memset(req, 0, 4 + paquet_size);
  req[0] = p->magic;
  req[1] = p->version;
  *((uint16_t*)&req[2]) = htole16(be16toh(paquet_size));
  memcpy(&req[4], tlvList, paquet_size);

  if (req[0] != 95) return NULL;
  if (req[1] != 1) return NULL;
  if (4 + paquet_size > PAQUET_SIZE) return NULL;

  return req;
}
