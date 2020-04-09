#ifndef structs
#define structs

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct {
  uint64_t id;
  uint16_t seqno;
  char data[];
} donnee;

typedef struct {
  struct sin6_addr* ip;
  struct sin6_port* port;
} socket;

typedef struct {
  socket s;
  char permanent;
  time_t last_change;
} voisin;

typedef struct {
  uint8_t type;
  size_t length;
  socket s;
  uint16_t network_hash;
  uint16_t node_hash;
  donnee data;
} tlv;

int sum(uint16_t seqno, int n);
int less_or_equals(uint16_t seqno1, uint16_t seqno2);
uint64_t random_id();

#endif
