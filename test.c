#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "constantes.h"
#include "hash.h"
#include "modele.h"
#include "parser.h"
#include "tlv.h"

int main(int argc, char const* argv[]) {
  int nbVoisins = 0;
  int* pointerNbVoisins = &nbVoisins;

  if (fork()) {
    sleep(5);
  }

  (*pointerNbVoisins)++;
  printf("fils : %d, %d, %d, %d\n", *pointerNbVoisins, &nbVoisins,
         pointerNbVoisins, nbVoisins);
  return 0;
}
