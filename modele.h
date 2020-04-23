#ifndef MODELE
#define MODELE

#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>

typedef struct {
  uint64_t id;
  uint16_t seqno;
  size_t length;
  char data[];
} donnee;

typedef struct {
  struct in6_addr ip;
  in_port_t port;
} addr;

typedef struct {
  addr s;
  char permanent;
  time_t last_change;
} voisin;

typedef struct {
  uint8_t type;
  addr address;
  __uint128_t network_hash;
  __uint128_t node_hash;
  donnee* data;
} tlv;

typedef struct {
  uint8_t magic;
  uint8_t version;
  size_t length;
  tlv* body[];
} paquet;

uint16_t sum(uint16_t seqno, int n);
char less_or_equals(uint16_t seqno1, uint16_t seqno2);
uint64_t random_id();

#endif
