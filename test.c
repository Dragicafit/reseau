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

// tester htons

int test(int argc, char const* argv[]) {
  char test[] = {1, 2, 3, 4};
  int data = 0;
  for (int i = 0; i < 4; i++) {
    ((uint8_t*)&data)[4 - (i + 1)] = test[i];
  }
  printf("%x\n", data);
  data = 0;
  int i = 0;
  for (int j = 4 - 1; j >= 0; j--) data += (test[i++] << (j * 8));
  printf("%x\n", data);
  return 0;
}
