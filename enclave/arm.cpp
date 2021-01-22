#include <stdint.h>
#include <unistd.h>

#include <openssl/bn.h>
#include "openssl/rand.h"

#include "sgx_urts.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "../cryptoki/pkcs11.h"

#include "ssss.h"

#define ROOTKEY_LENGTH 32
#define PRIME "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43"

uint8_t rootKey[ROOTKEY_LENGTH];
CK_BBOOL rootKeySet = CK_FALSE;

const uint8_t *getRootKey(size_t *length){
    if (length) *length = sizeof rootKey;
    if (rootKeySet == CK_TRUE) {
        return rootKey;
    }
    return NULL;
}


int SetRootKeyShare(int x, const uint8_t *y, size_t y_length, int threshold)
{
	static int local_threshold = 0;
	static int *x_s = NULL;
	static BIGNUM **y_s = NULL;
	static int nr_shares = 0;

	if (SGX_SUCCESS != sgx_read_rand(rootKey, ROOTKEY_LENGTH)) goto setRootKeyShare_err;
	if (x_s == NULL) {
		local_threshold = threshold;
	}
	if (threshold != local_threshold) return -3;
	rootKeySet = CK_FALSE;
	if (threshold < 2) return -1;
	for (int i=0; i<nr_shares; i++) if (x_s[i] == x) return -2;
	x_s = (int *) realloc(x_s, sizeof *x_s * (nr_shares + 1));
	x_s[nr_shares] = x;
	y_s = (BIGNUM **) realloc(y_s, sizeof *y_s * (nr_shares + 1));
	y_s[nr_shares] = BN_new();
	BN_bin2bn(y, y_length, y_s[nr_shares]);
	x_s[nr_shares] = x;
	nr_shares += 1;
	if (nr_shares == threshold) {
		BIGNUM *res = BN_new();
		BIGNUM *prime = NULL;
		BN_hex2bn(&prime, PRIME);
		lagrange_interpolate(res, 0, x_s, y_s, nr_shares, prime);
		BN_bn2bin(res, rootKey);
		rootKeySet = CK_TRUE;
		local_threshold = 0;
		free(x_s); x_s = NULL;
		free(y_s); y_s = NULL;
		return 1;
	}
setRootKeyShare_err:
	return 0;
}

int SetRootKeySealed(const uint8_t *root_key_sealed, size_t root_key_len_sealed){
    uint32_t decrypted_text_length = sizeof rootKey;
	sgx_status_t stat;

    rootKeySet = CK_FALSE;
    if ((SGX_SUCCESS != (stat = sgx_unseal_data(
            (const sgx_sealed_data_t *)root_key_sealed,
            NULL, NULL,
            rootKey, &decrypted_text_length))))
        return -1;
    rootKeySet = CK_TRUE;
    return 0;
}

int GetSealedRootKeySize(size_t *rootKeyLength){
    *rootKeyLength = sizeof(sgx_sealed_data_t) + ROOTKEY_LENGTH;
    return 0;
}

int GetRootKeySealed(uint8_t *root_key_sealed, size_t root_key_len_sealed, size_t *rootKeyLenSealed){
	sgx_status_t stat;
    //static uint8_t rootKey[ROOTKEY_LENGTH];

    if (GetSealedRootKeySize(rootKeyLenSealed)) return -1;
    if (*rootKeyLenSealed > root_key_len_sealed) {
        return -1;
    }
    if ((SGX_SUCCESS != (stat = sgx_seal_data(
            0, NULL, sizeof(rootKey), (const uint8_t *)rootKey, sizeof rootKey, (sgx_sealed_data_t *)root_key_sealed))))
        return -1;
    return 0;
}


int GenerateRootKey(uint8_t *rootKeySealed, size_t root_key_length, size_t *rootKeyLength){
    uint32_t sealedSize;
	sgx_status_t stat;
    rootKeySet = CK_FALSE;
    if (!RAND_bytes(rootKey, sizeof rootKey)) {
        return -1;
    }
    if ((sealedSize = sgx_calc_sealed_data_size(0, sizeof rootKey)) == UINT32_MAX)
        return -1;
    if (sealedSize > root_key_length)
        return -1;
    if ((SGX_SUCCESS != (stat = sgx_seal_data(
            0, NULL, sizeof(rootKey), (const uint8_t *)rootKey, root_key_length, (sgx_sealed_data_t *)rootKeySealed))))
        return -1;
    rootKeySet = CK_TRUE;
    return 0;
}


