#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>

#include "nts.h"

enum NTS_record_type {
	/* critical */
	NTS_EndOfMessage = 0,
	NTS_NextProto = 1,
	NTS_Error = 2,
	NTS_Warning = 3,
	/* may be critical */
	NTS_AEADAlgorithm = 4,
	/* never critical */
	NTS_NTPv4Cookie = 5,
	/* never critical by clients, may be critical by servers */
	NTS_NTPv4Server = 6,
	NTS_NTPv4Port = 7,
};

enum NTS_error_type {
	NTS_ERROR_UNKNOWN_CRIT_RECORD = 0,
	NTS_BAD_REQUEST = 1,
	NTS_INTERNAL_SERVER_ERROR = 2,

	NTS_UNEXPECTED_WARNING = 0x7FFE,
	NTS_INTERNAL_CLIENT_ERROR = 0x7FFF,
};

enum NTS_protocol_type {
	NTS_NTPv4 = 0,
	NTS_NTPv5 = 0x8001,
};

typedef struct {
	unsigned char *data;
	const unsigned char *data_end;
} slice;

/* does not check bounds */
static size_t capacity(slice *slice) {
	return slice->data_end - slice->data;
}

static void push_u16(unsigned char **data, uint16_t value) {
	value = htons(value);
	memcpy(*data, &value, 2);
	*data += 2;
}

static uint16_t u16_from_bytes(unsigned char bytes[2]) {
	uint16_t value;
	memcpy(&value, bytes, 2);
	return ntohs(value);
}

struct NTS_record {
	uint16_t type;
	slice body;
};

static int32_t NTS_decode_u16(struct NTS_record *record) {
	if(capacity(&record->body) < 2) {
		return -1;
	}

	uint16_t result = u16_from_bytes(record->body.data);
	record->body.data += 2;
	return result;
}

static int NTS_decode_record(slice *message, struct NTS_record *record) {
	size_t bytes_remaining = capacity(message);
	if(bytes_remaining < 4) {
		/* not enough byte to decode a header */
		return -1;
	}

	bool is_critical = message->data[0] >> 7;

	uint16_t body_size = u16_from_bytes(message->data + 2);
	if(body_size > bytes_remaining - 4) {
		/* not enough data in the slice to decode this header */
		return -2;
	}

	record->type = u16_from_bytes(message->data) & 0x7FFF;
	record->body.data = message->data += 4;
        record->body.data_end = message->data += body_size;

	switch(record->type) {
		case NTS_Error:
		case NTS_Warning:
		case NTS_NTPv4Port:
			if(body_size != 2) goto error;
			break;
		case NTS_EndOfMessage:
			if(body_size != 0) goto error;
			break;
		case NTS_AEADAlgorithm:
		case NTS_NextProto:
			if(body_size % 2 != 0) goto error;
			break;
		default:
			if(is_critical) {
				return -3;
			}
			break;
		case NTS_NTPv4Server:
		case NTS_NTPv4Cookie:
			break;
	}
	
	return 0;

error:
	/* there was an inconsistency in the record */
	return -4;
}

static int NTS_encode_record_u16(slice *message, bool critical, enum NTS_record_type type, const uint16_t *data, size_t num_words) {
	size_t bytes_remaining = capacity(message);
	if(num_words >= 0x8000 || bytes_remaining < 4 + num_words*2) {
		/* not enough space */
		return -1;
	}

	if(critical) {
		type |= 0x8000;
	}

	push_u16(&message->data, type);
	push_u16(&message->data, num_words * 2);

	for(size_t i = 0; i < num_words; i++) {
		push_u16(&message->data, data[i]);
	}

	return 0;
}

/* only used for testing */
static int NTS_encode_record_str(slice *message, bool critical, enum NTS_record_type type, const unsigned char *data, size_t len) {
	size_t bytes_remaining = capacity(message);
	if(bytes_remaining < 4 + len) {
		/* not enough space */
		return -1;
	}

	if(critical) {
		type |= 0x8000;
	}

	push_u16(&message->data, type);
	push_u16(&message->data, len);

	memcpy(message->data, data, len);
	message->data += len;

	return 0;
}

#define ELEMS(array) (sizeof(array) / sizeof(*array))

extern int NTS_encode_request(unsigned char *buffer, size_t buf_size, const NTS_AEAD_algorithm_type *preferred_crypto);

int NTS_encode_request(unsigned char *buffer, size_t buf_size, const NTS_AEAD_algorithm_type *preferred_crypto) {
	slice request = { buffer, buffer + buf_size };

	const uint16_t proto[] = { NTS_NTPv4 };
	const uint16_t aead_default[] = { NTS_AEAD_AES_SIV_CMAC_256 }, *aead = aead_default;
	size_t aead_len = ELEMS(aead_default);
	if(preferred_crypto) {
		aead = preferred_crypto;
		for(aead_len = 0; preferred_crypto[aead_len] ; ) ++aead_len;
	}

	int result;
	result  = NTS_encode_record_u16(&request, true, NTS_NextProto, proto, ELEMS(proto));
	result += NTS_encode_record_u16(&request, true, NTS_AEADAlgorithm, aead, aead_len);
	result += NTS_encode_record_u16(&request, true, NTS_EndOfMessage, NULL, 0);

	return (result<0)? result : request.data - buffer;
}

struct NTS_response {
	uint16_t result; /* NTS_error encoding + 1 */
};

#include <stdio.h>
void dump_packet(unsigned char *buffer, size_t len) {
        slice response = { buffer, buffer+len };
        struct NTS_record rec;
        while(response.data < response.data_end) {
            int result = NTS_decode_record(&response, &rec);
            int i;
            if(result < 0) {
                printf("decode failed[%d]: type %u\n", result, rec.type);
            }
            switch(rec.type) {
                case NTS_Error:
                    printf("error %u\n", NTS_decode_u16(&rec));
                    break;
                case NTS_EndOfMessage:
                    printf("end of message\n");
                    break;
                case NTS_NextProto:
                    printf("offered protocols: ");
                    while((i = NTS_decode_u16(&rec)) >= 0) printf("%u, ", i);
                    printf("\n");
                    break;
                case NTS_AEADAlgorithm:
                    printf("offered algorithms: ");
                    while((i = NTS_decode_u16(&rec)) >= 0) printf("%u, ", i);
                    printf("\n");
                    break;
                case NTS_NTPv4Cookie:
                    printf("yumyum: ");
                    for(unsigned char *p = rec.body.data; p != rec.body.data_end; p++) printf("%02x", *p);
                    printf("\n");
                    break;
                case NTS_NTPv4Port:
                    printf("ntp port: %u\n", NTS_decode_u16(&rec));
                    break;
                case NTS_NTPv4Server:
                    printf("ntp server: <%*.s>\n", (int)capacity(&rec.body), rec.body.data);
                    break;
                default:
                    printf("unknown record type %d\n", rec.type);
            }
        }

}
