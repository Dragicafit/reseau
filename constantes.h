#ifndef CONSTANTES
#define CONSTANTES

#define handle_error(msg) \
  do {                    \
    perror(msg);          \
    exit(EXIT_FAILURE);   \
  } while (0)

#define bigIndia(i, req, data, size)                                   \
  {                                                                    \
    data = 0;                                                          \
    for (int j = size - 1; j >= 0; j--) data += (req[i++] << (j * 8)); \
  }

#define PAQUET_SIZE 1024
#define NB_TLV_MAX PAQUET_SIZE - 4
#define DATA_SIZE 192
#define VOISINS_SIZE 100
#define DONNEES_SIZE 1000
#define MAX_VOISINS 15

#endif