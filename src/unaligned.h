#include <ctype.h>
#include <arpa/inet.h>

inline void unaligned_write_be16(void *buf, uint16_t value) 
{
    value = htons(value);
    memcpy(buf, &value, 2);
}

inline uint16_t unaligned_read_be16(void *buf) 
{
    uint16_t value;
    memcpy(&value, buf, 2);
    return ntohs(value);
}
