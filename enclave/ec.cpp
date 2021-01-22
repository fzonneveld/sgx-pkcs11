#include "ec.h"
#include <openssl/bn.h>

EC_KEY *generateEC(uint8_t *ec_paramaters, size_t ec_parameters_len) {
    // EC_PARAM
    // EC_group_new()
    // EC_KEY_new_by_curve_name();
    EC_KEY *key = NULL, *ret = NULL;
    EC_GROUP *grp = NULL;

	const uint8_t *endptr = (const uint8_t *) ec_paramaters;
    if ((key = EC_KEY_new()) == NULL) goto generateEC_err;
    if ((grp = d2i_ECPKParameters(NULL, &endptr, ec_parameters_len)) == NULL) goto generateEC_err;
    EC_KEY_set_group(key, grp);
    if (!EC_KEY_generate_key(key)) goto generateEC_err;
    ret = key;
    key = NULL;
generateEC_err:
    if (key) EC_KEY_free(key);
    if (grp) EC_GROUP_free(grp);
    return ret;
}


int SGXgenerateECKeyPair(
        uint8_t *RSAPublicKey, size_t RSAPublicKeyLength, size_t *RSAPublicKeyLengthOut,
        uint8_t *RSAPrivateKey, size_t RSAPrivateKeyLength, size_t *RSAPrivateKeyLengthOut,
		const uint8_t *pSerialAttr, size_t serialAttrLen) {
	return 0;
}


uint8_t *ECDSAsign(
        const uint8_t *private_key_der, size_t privateKeyDERlength,
        const uint8_t *dgst, int dgstlen,
        unsigned int *siglen)
{
    uint8_t *sig = NULL, *ret = NULL;

    const EC_GROUP *grp = NULL;
    const BIGNUM *order = NULL;
    EC_KEY *key;

    key = d2i_ECPrivateKey(NULL, &private_key_der, privateKeyDERlength);
    grp = EC_KEY_get0_group(key);
    order = BN_new();

    if (!key or !grp) goto ECDSAsign_err;
    if ((order = EC_GROUP_get0_order(grp)) == NULL) goto ECDSAsign_err;
    *siglen = BN_num_bytes(order) * 2; // both r,s
    if ((sig = (uint8_t *)malloc(*siglen * sizeof *sig)) == NULL) goto ECDSAsign_err;
    if (ECDSA_sign(0, dgst, dgstlen, sig, siglen, key) == 0) goto ECDSAsign_err;
    ret = sig;
    sig = NULL;
ECDSAsign_err:
    if (key) EC_KEY_free(key);
    if (sig) free(sig);
    return ret;
}
