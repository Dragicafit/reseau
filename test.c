#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

#include <arpa/inet.h>
#include <endian.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// tester htons

int test(int argc, char const* argv[]) {
  char test[] = {1, 2};
  printf("%x\n", ntohs(*(uint16_t*)&test[0]));

  printf("%d\n", htons(12));
  return 0;
}
