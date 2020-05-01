#ifndef CONSTANTES
#define CONSTANTES

#define handle_error(msg) \
  do {                    \
    perror(msg);          \
    exit(EXIT_FAILURE);   \
  } while (0)

#define max(a, b)           \
  ({                        \
    __typeof__(a) _a = (a); \
    __typeof__(b) _b = (b); \
    _a > _b ? _a : _b;      \
  })

#define min(a, b)           \
  ({                        \
    __typeof__(a) _a = (a); \
    __typeof__(b) _b = (b); \
    _a < _b ? _a : _b;      \
  })

#define PORT 3001
#define PAQUET_SIZE 1024
#define NB_TLV_MAX PAQUET_SIZE - 4
#define DATA_SIZE 192
#define VOISINS_SIZE 100
#define DONNEES_SIZE 1000
#define MAX_VOISINS 15
#define INTERVAL_20 20
#define INTERVAL_70 70
#define MAX_SEND_TLV2 5

#endif