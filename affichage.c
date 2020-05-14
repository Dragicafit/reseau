#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "constantes.h"
#include "modele.h"

int printDebug(const char* format, ...) {
  if (!debug) return 0;
  va_list vl;
  va_start(vl, format);
  int ret = vprintf(format, vl);
  va_end(vl);
  return ret;
}

void printPaquet(paquet* p) {
  printDebug("magic : \t\t%hhu\n", p->magic);
  printDebug("version : \t\t%hhu\n", p->version);
  printDebug("nb tlv : \t\t%lu\n", p->length);
  char ip[INET6_ADDRSTRLEN];

  for (int i = 0; i < p->length; i++) {
    tlv* t = p->body[i];
    if (t->type == 0) {
      i++;
      continue;
    }
    printDebug("type : \t\t\t%hhu\n", t->type);

    switch (t->type) {
      case 3:
        inet_ntop(AF_INET6, &t->address.ip, ip, INET6_ADDRSTRLEN);
        printDebug("ip : \t\t\t%s:%hu\n", ip, ntohs(t->address.port));
        break;
      case 4:
        printDebug("network hash : \t\t%lx%lx\n",
                   ((uint64_t*)&t->network_hash)[0],
                   ((uint64_t*)&t->network_hash)[1]);
        break;
      case 6:
        printDebug("id : \t\t\t%lu\n", t->data->id);
        printDebug("seqno : \t\t%hu\n", t->data->seqno);
        printDebug("node hash : \t\t%lx%lx\n",
                   ((uint64_t*)&t->data->node_hash)[0],
                   ((uint64_t*)&t->data->node_hash)[1]);
        break;
      case 7:
        printDebug("id : \t\t\t%lu\n", t->data->id);
        break;
      case 8:
        printDebug("length : \t\t%lu\n", t->data->length);
        printDebug("id : \t\t\t%lu\n", t->data->id);
        printDebug("seqno : \t\t%hu\n", t->data->seqno);
        printDebug("node hash : \t\t%lx%lx\n",
                   ((uint64_t*)&t->data->node_hash)[0],
                   ((uint64_t*)&t->data->node_hash)[1]);
        printDebug("data : \t\t\t%s\n", t->data->data);
        break;
      case 9:
        printDebug("length : \t\t%lu\n", t->data->length);
        printDebug("warning : \t\t%s\n", t->data->data);
        break;
      default:
        break;
    }
    printDebug("\n");
  }
}
