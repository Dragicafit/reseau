#ifndef structs
#define structs

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct {
    uint64_t i;
    uint16_t seqno;
    char* data;
} donnee;

typedef struct {
    struct sin6_addr* ip;
    uint16_t port;
} socket;

typedef struct {
    socket s;
    int permanent;
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

#endif
