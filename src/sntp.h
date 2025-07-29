#pragma once

#define ntp_poll(host, port, roundtrip_delay, time_offset) nts_poll(host, port, NULL, roundtrip_delay, time_offset)

struct NTS_Query;

void nts_poll(const char *host, int port, struct NTS_Query *cfg, double *roundtrip_delay, double *time_offset);
