#include <sys/random.h>
#define crypto_random_bytes(x,y) (getrandom(x,y,0) == -1)
