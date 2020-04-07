#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <stdbool.h>
#include <time.h>

#include "modele.h"

int sum(uint16_t seqno, int n) {
    return (seqno + n) % (int)pow(2, 16);
}

int less_or_equals(uint16_t seqno1, uint16_t seqno2){
    return (seqno2 - seqno1) & 32768 == 0;
}

uint64_t random_id() {
    srand( time( NULL ) );
    return (uint64_t) rand % (int) (pow(2, 63)) - 1;
}
