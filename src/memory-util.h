#ifndef memzero
#define memzero(x,l) (memset(x, 0, l))
#endif
#ifndef zero
#define zero(x) (memzero(&(x), sizeof(x)))
#endif

#ifndef ELEMENTSOF
#define ELEMENTSOF(array) (sizeof(array) / sizeof(*array))
#endif
