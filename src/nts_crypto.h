#pragma once

#include "nts.h"
#include "nts_extfields.h"

typedef struct {
	const unsigned char *data;
	const size_t length;
} associated_data;

/* encrypt the data in ptxt of ptxt_len bytes, and write it to ctxt, using the cryptoscheme selected in the NTS_query
 * the associated data should point to an array of NULL-terminated chunks of associated data
 *
 * caller should make sure that there is enough room in ptxt for holding the plaintext + one additional block
 * if ctxt and ptxt overlap, they should be at least one blocksize of bytes apart
 *
 * RETURNS: the number of bytes in the ciphertext (< 0 indicates an error)
 */
int NTS_encrypt(unsigned char *ctxt, const unsigned char *ptxt, int ptxt_len, const associated_data *, const struct NTS_query *);

/* decrypt the data in ctxt of ctxt_len bytes, and write it to ptxt, using the cryptoscheme selected in the NTS_query
 *
 * the associated data should point to an array of NULL-terminated chunks of associated data
 *
 * caller should make sure that there is enough room in ptxt for holding the decrypted ciphertext; the size of the
 * plaintext will always be less than or equal to the ciphertext ptxt
 * if ctxt and ptxt overlap, they should be at least one blocksize of bytes apart
 *
 * RETURNS: the number of bytes in the decrypted plaintext (< 0 indicates an error)
 */
int NTS_decrypt(unsigned char *ptxt, const unsigned char *ctxt, int ctxt_len, const associated_data *, const struct NTS_query *);
