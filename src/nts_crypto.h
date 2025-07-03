#pragma once

#include "nts.h"
#include "nts_extfields.h"

typedef struct {
	const unsigned char *data;
	const size_t length;
} associated_data;

/* the associated data should point to an array of NULL-terminated chunks of associated data
 *
 * caller should make sure that there is enough room in ptxt for holding the plaintext + one additional block */
int NTS_encrypt(unsigned char *ctxt, const unsigned char *ptxt, int ptxt_len, const associated_data *, const struct NTS_query *);

/* the associated data should point to an array of NULL-terminated chunks of associated data
 *
 * caller should make sure that there is enough room in ptxt for holding the decrypted ciphertext; the size of the
 * plaintext will always be less than or equal to the ciphertext ptxt and ctxt are allowed to point to overlapping
 * regions of memory */
int NTS_decrypt(unsigned char *ptxt, const unsigned char *ctxt, int ctxt_len, const associated_data *, const struct NTS_query *);
