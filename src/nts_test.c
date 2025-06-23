#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <assert.h>

#include "nts.h"

/* it's the callers job to ensure bounds are not transgressed */
static void encode_record_raw(unsigned char **message, uint16_t type, const void *data, uint16_t len) {
	unsigned char hdr[] = {
		type >> 8,
		type & 0xFF,
		len >> 8,
		len & 0xFF,
	};

	memcpy(*message, hdr, 4);
	memcpy(*message+4, data, len);
	*message += len + 4;
}

void test_encoding(void) {
	unsigned char buffer[1000];
	struct NTS_response rec;

	NTS_encode_request(buffer, sizeof buffer, NULL);
	assert(NTS_decode_response(buffer, 1000, &rec) == 0);
	assert(rec.error == NTS_SUCCESS);
	assert(rec.ntp_server == NULL);
	assert(rec.ntp_port == 0);
	assert(rec.cookie[0].data == NULL);
	assert(rec.cookie[0].length == 0);
	assert(rec.aead_id == NTS_AEAD_AES_SIV_CMAC_256);

	uint16_t proto1[] = { NTS_AEAD_AES_SIV_CMAC_256, NTS_AEAD_AES_SIV_CMAC_512, 0 };
	NTS_encode_request(buffer, sizeof buffer, proto1);
	assert(NTS_decode_response(buffer, 1000, &rec) == 0);
	assert(rec.error == NTS_SUCCESS);
	assert(rec.ntp_server == NULL);
	assert(rec.ntp_port == 0);
	assert(rec.cookie[0].data == NULL);
	assert(rec.cookie[0].length == 0);
	assert(rec.aead_id == NTS_AEAD_AES_SIV_CMAC_256);

	uint16_t proto2[] = { NTS_AEAD_AES_SIV_CMAC_512, NTS_AEAD_AES_SIV_CMAC_256, 0 };
	NTS_encode_request(buffer, sizeof buffer, proto2);
	assert(NTS_decode_response(buffer, 1000, &rec) == 0);
	assert(rec.error == NTS_SUCCESS);
	assert(rec.ntp_server == NULL);
	assert(rec.ntp_port == 0);
	assert(rec.cookie[0].data == NULL);
	assert(rec.cookie[0].length == 0);
	assert(rec.aead_id == NTS_AEAD_AES_SIV_CMAC_512);
}

void test_decoding(void) {
	unsigned char buffer[0x10000], *p;
	struct NTS_response rec;

	/* empty */
	uint8_t value[2] = { 0, };
	encode_record_raw((p = buffer, &p), 0, NULL, 0);
	assert(NTS_decode_response(buffer, sizeof buffer, &rec) != 0);
	assert(rec.error == NTS_BAD_RESPONSE);

	/* missing aead */
	encode_record_raw((p = buffer, &p), 1, &value, 2);
	encode_record_raw(&p, 0, NULL, 0);
	assert(NTS_decode_response(buffer, sizeof buffer, &rec) != 0);
	assert(rec.error == NTS_BAD_RESPONSE);

	/* missing next proto */
	encode_record_raw((p = buffer, &p), 4, (value[1] = 15, &value), 2);
	encode_record_raw(&p, 0, NULL, 0);
	assert(NTS_decode_response(buffer, sizeof buffer, &rec) != 0);
	assert(rec.error == NTS_BAD_RESPONSE);

	/* valid */
	encode_record_raw((p = buffer, &p), 1, (value[1] = 0, &value), 2);
	encode_record_raw(&p, 5, "COOKIE1", 7);
	encode_record_raw(&p, 4, (value[1] = 15, &value), 2);
	encode_record_raw(&p, 5, "COOKIE22", 8);
	encode_record_raw(&p, 7, (value[1] = 42, &value), 2);
	encode_record_raw(&p, 5, "COOKIE333", 9);
	encode_record_raw(&p, 6, "localhost", 9);
	encode_record_raw(&p, 5, "COOKIE4444", 10);
	assert(NTS_decode_response(buffer, sizeof buffer, &rec) == 0);
	assert(rec.error == NTS_SUCCESS);
	assert(rec.aead_id == 15);
	assert(rec.ntp_port == 42);
	assert(strcmp(rec.ntp_server, "localhost") == 0);
	assert(memcmp(rec.cookie[0].data, "COOKIE1", rec.cookie[0].length) == 0);
	assert(memcmp(rec.cookie[1].data, "COOKIE22", rec.cookie[1].length) == 0);
	assert(memcmp(rec.cookie[2].data, "COOKIE333", rec.cookie[2].length) == 0);
	assert(memcmp(rec.cookie[3].data, "COOKIE4444", rec.cookie[3].length) == 0);
	assert(rec.cookie[4].data == NULL);
	assert(rec.cookie[4].length == 0);
}

int main(void) {
	test_encoding();
	test_decoding();
	return 0;
}
