#define ntp_poll(host, port, roundtrip_delay, time_offset) nts_poll(host, port, NULL, NULL, roundtrip_delay, time_offset)

struct NTS;
typedef int callback(unsigned char(*)[1280], const struct NTS *);

void nts_poll(const char *host, int port, const struct NTS *cfg, callback fun, double *roundtrip_delay, double *time_offset);
