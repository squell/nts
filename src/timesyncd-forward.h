#include <assert.h>
#include "memory-util.h"

#define FOREACH_ARRAY(i, array, num)                                    \
        for (typeof(array[0]) *i = (array), *end = ({                   \
                                typeof(num) _m = (num);                 \
                                (i && _m > 0) ? i + _m : NULL;          \
                        }); end && i < end; i++)

#define FOREACH_ELEMENT(i, array)                                 \
        FOREACH_ARRAY(i, array, ELEMENTSOF(array))


