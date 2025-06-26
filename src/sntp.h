#pragma once

#define ntp_poll(host, port, roundtrip_delay, time_offset) nts_poll(host, port, NULL, roundtrip_delay, time_offset)

struct NTS_query;

void nts_poll(const char *host, int port, struct NTS_query *cfg, double *roundtrip_delay, double *time_offset);
