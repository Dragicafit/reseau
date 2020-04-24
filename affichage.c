
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "constantes.h"
#include "modele.h"

void printPaquet(paquet* p) {
  printf("magic : \t\t%hhu\n", p->magic);
  printf("version : \t\t%hhu\n", p->version);
  printf("nb tlv : \t\t%lu\n", p->length / sizeof(tlv*));
  char ip[INET6_ADDRSTRLEN];

  for (int i = 0; i < p->length / sizeof(tlv*); i++) {
    tlv* t = p->body[i];
    if (t->type == 0) {
      i++;
      continue;
    }
    printf("type : \t\t\t%hhu\n", t->type);

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
        printf("length : \t\t%lu\n", t->data->length);
        printf("id : \t\t\t%lu\n", t->data->id);
        printf("seqno : \t\t\t%hu\n", t->data->seqno);
        printf("node hash : \t\t%lx%lx\n", ((uint64_t*)&t->node_hash)[0],
               ((uint64_t*)&t->node_hash)[1]);
        printf("data : \t\t\t%s\n", t->data->data);
        break;
      case 9:
        printf("length : \t\t%lu\n", t->data->length);
        printf("warning : \t\t%s\n", t->data->data);
        break;
      default:
        break;
    }
    printf("\n");
  }
  fflush(stdout);
}
