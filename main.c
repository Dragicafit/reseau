#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

#include <arpa/inet.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "affichage.h"
#include "constantes.h"
#include "hash.h"
#include "modele.h"
#include "parser.h"
#include "tlv.h"

gboolean debug = FALSE;
static gboolean ipv6 = FALSE;

static GOptionEntry entries[] = {
    {"debug", 'd', 0, G_OPTION_ARG_NONE, &debug, "debug", NULL},
    {"ipv6", '6', 0, G_OPTION_ARG_NONE, &ipv6, "lancer avec ipv6", NULL},
    {NULL}};

uint64_t id = 0;
voisin* voisins[VOISINS_SIZE] = {NULL};
donnee* donnees[DONNEES_SIZE] = {NULL};
int nbVoisins = 0;
int nbDonnees = 0;

int main(int argc, char* argv[]) {
  srand(time(NULL));

  GError* error = NULL;
  GOptionContext* context;
  context = g_option_context_new("- test");
  g_option_context_add_main_entries(context, entries, NULL);

  if (!g_option_context_parse(context, &argc, &argv, &error)) {
    g_print("option parsing failed: %s\n", error->message);
    exit(1);
  }

  FILE* f = fopen("id.txt", "r+");
  if (f == NULL) {
    f = fopen("id.txt", "w+");
    if (f == NULL) {
      handle_error("Impossible de créer le fichier");
    }
  }

  fscanf(f, "%lu", &id);

  if (id == 0) {
    id = random_id();
    fprintf(f, "%lu", id);
  }
  fclose(f);

  printDebug("id : %lu\n", id);

  donnee* d = calloc(1, sizeof(donnee) + 25);
  d->id = id;
  memcpy(d->data, "nfghfghjkfghlkfjghlkfhjj", 25);
  d->length = 25;
  d->seqno = 0;
  d->node_hash = nodeHash(d);
  donnees[0] = d;

  nbDonnees++;

  int s, val = 1, rc;
  paquet* p;
  uint8_t req[PAQUET_SIZE] = {0};
  uint8_t* envoi;

  struct sockaddr_in6 addr, client, serv;
  socklen_t addr_len = sizeof(struct sockaddr_in6);
  socklen_t serv_len = sizeof(struct sockaddr_in6);
  socklen_t client_len = sizeof(struct sockaddr_in6);

  if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) handle_error("socket error");
  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0)
    handle_error("sockop error");

  memset(&addr, 0, addr_len);
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(PORT);

  if (bind(s, (struct sockaddr*)&addr, addr_len) < 0)
    handle_error("bind s error");

  printDebug("Ouverture du serveur sur le port %d\n", PORT);

  memset(&serv, 0, serv_len);
  serv.sin6_family = AF_INET6;
  serv.sin6_port = htons(1212);
  char ipv4[INET6_ADDRSTRLEN] = "::ffff:";
  if (inet_pton(AF_INET6, ipv6 ? IPV6_PROF : strcat(ipv4, IPV4_PROF),
                &serv.sin6_addr) < 1)
    handle_error("inet error");

  voisins[0] = calloc(1, sizeof(voisin));
  voisins[0]->permanent = 1;
  memcpy(&voisins[0]->s.ip, &serv.sin6_addr, sizeof(struct in6_addr));
  voisins[0]->s.port = serv.sin6_port;
  voisins[0]->last_change = time(NULL);
  nbVoisins++;

  printDebug("Ajout du serveur dans la liste des voisins\n");

  time_t tempsDebut = time(NULL);
  while (1) {
    if (tempsDebut + INTERVAL_20 <= time(NULL)) {
      tempsDebut = time(NULL);
      for (int i = 0; i < nbVoisins; i++) {
        voisin* v = voisins[i];
        paquet* p = creerPaquetTlv4(donnees, nbDonnees);
        envoi = arcParser(p);
        rc = sendto(s, envoi, ntohs(*(uint16_t*)&envoi[2]) + 4, 0,
                    addrToSockaddr(&v->s), sizeof(struct sockaddr_in6));
        if (rc < 0) handle_error("select error");
        printDebug("Envoi d'un TLV4 a un voisin\n");

        printPaquet(p);

        if (voisins[i]->permanent) continue;

        if (voisins[i]->last_change + INTERVAL_70 <= time(NULL)) {
          free(voisins[i]);
          nbVoisins--;
          voisins[i] = voisins[nbVoisins];
        }
      }

      if (nbVoisins > MAX_SEND_TLV2) continue;
      if (nbVoisins < 1) continue;

      voisin* v = voisins[rand() % nbVoisins];
      paquet* p = creerPaquetTlv2();
      envoi = arcParser(p);
      rc = sendto(s, envoi, ntohs(*(uint16_t*)&envoi[2]) + 4, 0,
                  addrToSockaddr(&v->s), sizeof(struct sockaddr_in6));
      if (rc < 0) handle_error("select error");
      printDebug("Envoi d'un TLV2 a un voisin aléatoire\n");

      printPaquet(p);
    }

    fd_set set;
    struct timeval timeout;
    FD_ZERO(&set);
    FD_SET(s, &set);
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    int rv = select(s + 1, &set, NULL, NULL, &timeout);
    if (rv < 1) continue;

    rc = recvfrom(s, req, PAQUET_SIZE, 0, (struct sockaddr*)&client,
                  &client_len);
    if (rc < 0) handle_error("recvf error");

    printDebug("Réception d'un paquet\n");

    char ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &client.sin6_addr, ip, INET6_ADDRSTRLEN);
    printDebug("ip : \t\t\t%s:%hu\n", ip, ntohs(client.sin6_port));

    p = parser(req);
    if (p == NULL) continue;

    int present = -1;
    for (int i = 0; i < nbVoisins; i++) {
      if (sock_addr_cmp_addr(&voisins[i]->s, &client)) {
        present = i;
        break;
      }
    }
    printDebug("Vérification de la présence\n");

    if (present == -1) {
      if (nbVoisins >= MAX_VOISINS) continue;
      present = nbVoisins;
      voisins[present] = calloc(1, sizeof(voisin));
      voisins[present]->permanent = 0;
      memcpy(&voisins[present]->s.ip, &client.sin6_addr,
             sizeof(struct in6_addr));
      voisins[present]->s.port = client.sin6_port;
      nbVoisins++;
      printDebug("Voisin ajouté\n");
    }
    voisins[present]->last_change = time(NULL);

    for (int i = 0; i < p->length / sizeof(tlv*); i++) {
      printDebug("Gestion du tlv n°%d\n", i);
      tlv* t = p->body[i];
      paquet* p;
      voisin* v;
      donnee* d = NULL;
      int position;
      switch (t->type) {
        case 2:
          v = voisins[rand() % nbVoisins];
          p = creerPaquetTlv3(&v->s);
          envoi = arcParser(p);
          sendto(s, envoi, ntohs(*(uint16_t*)&envoi[2]) + 4, 0,
                 (struct sockaddr*)&client, client_len);
          printDebug("Envoi d'un tlv 3\n");
          printPaquet(p);
          break;
        case 3:
          p = creerPaquetTlv4(donnees, nbDonnees);
          envoi = arcParser(p);
          sendto(s, envoi, ntohs(*(uint16_t*)&envoi[2]) + 4, 0,
                 addrToSockaddr(&t->address), sizeof(struct sockaddr_in6));
          printDebug("Envoi d'un tlv 4\n");
          printPaquet(p);
          break;
        case 4:
          if (networkHash(donnees, nbDonnees) == t->network_hash) continue;
          p = creerPaquetTlv5();
          envoi = arcParser(p);
          sendto(s, envoi, ntohs(*(uint16_t*)&envoi[2]) + 4, 0,
                 (struct sockaddr*)&client, client_len);
          printDebug("Envoi d'un tlv 5\n");
          printPaquet(p);
          break;
        case 5:
          p = creerPaquetTlv6(donnees, nbDonnees);
          envoi = arcParser(p);
          sendto(s, envoi, ntohs(*(uint16_t*)&envoi[2]) + 4, 0,
                 (struct sockaddr*)&client, client_len);
          printDebug("Envoi d'une liste de tlv 6\n");
          printPaquet(p);
          break;
        case 6:
          for (int j = 0; j < nbDonnees; j++) {
            d = donnees[j];
            if (d->id != t->data->id) break;
          }
          if (d != NULL && d->node_hash == t->data->node_hash) continue;
          p = creerPaquetTlv7(t->data->id);
          envoi = arcParser(p);
          sendto(s, envoi, ntohs(*(uint16_t*)&envoi[2]) + 4, 0,
                 (struct sockaddr*)&client, client_len);
          printDebug("Envoi d'un tlv 7\n");
          printPaquet(p);
          break;
        case 7:
          for (int j = 0; j < nbDonnees; j++) {
            d = donnees[j];
            if (d->id == t->data->id) break;
          }
          if (d == NULL) continue;
          p = creerPaquetTlv8(d);
          envoi = arcParser(p);
          sendto(s, envoi, ntohs(*(uint16_t*)&envoi[2]) + 4, 0,
                 (struct sockaddr*)&client, client_len);
          printDebug("Envoi d'un tlv 8\n");
          printPaquet(p);
          break;
        case 8:
          for (int j = 0; j < nbDonnees; j++) {
            d = donnees[j];
            position = j;
            if (d->id == t->data->id) break;
          }
          if (t->data->id != id) {
            if (d == NULL) {
              if (nbDonnees >= DATA_SIZE) continue;
              donnees[nbDonnees++] = t->data;
              printDebug("Ajout d'un nouvelle donnée\n");
              continue;
            }
          }

          if (d->node_hash == t->data->node_hash) continue;

          if (t->data->id == id) {
            if (less_or_equals(d->seqno, t->data->seqno)) {
              d->seqno = sum(t->data->seqno, 1);
              printDebug("Changement du seqno\n");
            }
            continue;
          }

          if (!less_or_equals(t->data->seqno, d->seqno)) {
            free(d);
            donnees[position] = t->data;
            printDebug("Modification d'une donnée\n");
          }
          break;
        case 9:
          printDebug("Warning : %s", t->data->data);
          break;
        default:
          printDebug("Type inconu\n");
          continue;
      }
    }
  }

  close(s);
  return 0;
}
