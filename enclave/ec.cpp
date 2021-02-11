#include "ec.h"
#include <openssl/evp.h>
#include <openssl/x509.h>

EC_KEY *generateEC(const uint8_t *ec_paramaters, size_t ec_parameters_len) {
    // EC_PARAM
    // EC_group_new()
    // EC_KEY_new_by_curve_name();
    EC_KEY *key = NULL, *ret = NULL;
	EC_GROUP *pGrp = NULL;

	const uint8_t *endptr = ec_paramaters;
    if ((key = EC_KEY_new()) == NULL) goto generateEC_err;
    if ((pGrp = d2i_ECPKParameters(NULL, &endptr, ec_parameters_len)) == NULL) goto generateEC_err;
    EC_KEY_set_group(key, pGrp);
    if (!EC_KEY_generate_key(key)) goto generateEC_err;
    ret = key;
    key = NULL;
generateEC_err:
    if (key) EC_KEY_free(key);
	if (pGrp) EC_GROUP_free(pGrp);
    return ret;
}

static CK_KEY_TYPE keyType = CKK_EC;
static CK_BBOOL tr = CK_TRUE;
static CK_OBJECT_CLASS privObjecClass = CKO_PRIVATE_KEY;

static CK_ATTRIBUTE defaultPrivateKeyAttr[] = {
    {CKA_CLASS, &privObjecClass, sizeof privObjecClass},
    {CKA_KEY_TYPE, &keyType, sizeof keyType},
	{CKA_SENSITIVE, &tr, sizeof(tr)},
	{CKA_ALWAYS_SENSITIVE, &tr, sizeof(tr)}
};

static auto defaultPrivateKKeyAttrMap = ATTR(defaultPrivateKeyAttr).map();

static CK_OBJECT_CLASS pubObjectClass = CKO_PUBLIC_KEY;

static CK_ATTRIBUTE defaultPublicKeyAttr[] = {
    {CKA_CLASS, &pubObjectClass, sizeof pubObjectClass},
    {CKA_KEY_TYPE, &keyType, sizeof keyType},
};

static auto defaultPublicKeyAttrMap = ATTR(defaultPublicKeyAttr).map();


int generateECKeyPair(
        uint8_t **ppECPublicKey, size_t *pECPublicKeyLength,
        Attribute &pubAttr,
        uint8_t **ppECPrivateKey, size_t *pECPrivateKeyLength,
        Attribute &privAttr) {
    int ret = -1;
    int i2dret;
    EC_KEY *key = NULL;
    CK_ATTRIBUTE_PTR p;
	uint8_t *pPrivateKeyDER = NULL, *pPublicKeyDER = NULL;
	EVP_PKEY *evp_pkey = NULL;

    if ((p = pubAttr.get(CKA_EC_PARAMS)) == NULL) return -1;
	if ((key = generateEC((uint8_t *)p->pValue, p->ulValueLen)) ==NULL)
        return -1;

    pubAttr.merge(defaultPublicKeyAttrMap);
    privAttr.merge(defaultPrivateKKeyAttrMap);

	evp_pkey = EVP_PKEY_new();
	EVP_PKEY_set1_EC_KEY(evp_pkey, key);
    i2dret = i2d_PUBKEY(evp_pkey, NULL);
    if (i2dret < 0) goto generateECKeyPair_err;
	pPublicKeyDER = (uint8_t *) malloc(i2dret);
	*ppECPublicKey = pPublicKeyDER;
    i2dret = i2d_PUBKEY(evp_pkey, &pPublicKeyDER);
	pPublicKeyDER = NULL;
    *pECPublicKeyLength = i2dret;

    i2dret = i2d_ECPrivateKey(key, NULL);
	if (i2dret < 0) goto generateECKeyPair_err;
    i2dret = i2d_ECPrivateKey(key, &pPrivateKeyDER);
    if (i2dret < 0) goto generateECKeyPair_err;
    *pECPrivateKeyLength = i2dret;
	*ppECPrivateKey = pPrivateKeyDER;
	pPrivateKeyDER = NULL;
    ret = 0;
generateECKeyPair_err:
	if (pPrivateKeyDER) free(pPrivateKeyDER);
	if (pPublicKeyDER) free(pPublicKeyDER);
	if (evp_pkey) EVP_PKEY_free(evp_pkey);
    if (key) EC_KEY_free(key);
    return ret;
}



static uint8_t *ECDSAsign(
        const uint8_t *private_key_der, size_t privateKeyDERlength,
        const uint8_t *dgst, int dgstlen,
        unsigned int *siglen)
{
    uint8_t *sig = NULL, *ret = NULL;

    const EC_GROUP *grp = NULL;
    EC_KEY *key;

    if (NULL == (key = d2i_ECPrivateKey(NULL, &private_key_der, privateKeyDERlength))) goto ECDSAsign_err;
    grp = EC_KEY_get0_group(key);

    if (!key or !grp) goto ECDSAsign_err;
    *siglen = ECDSA_size(key);
    if ((sig = (uint8_t *)malloc(*siglen)) == NULL) goto ECDSAsign_err;
    if (ECDSA_sign(0, dgst, dgstlen, sig, siglen, key) == 0) goto ECDSAsign_err;
    ret = sig;
    sig = NULL;
ECDSAsign_err:
    if (key) EC_KEY_free(key);
    if (sig) free(sig);
    return ret;
}


typedef const EVP_MD* (*md_func_t)(void);

static std::map<CK_MECHANISM_TYPE, md_func_t> allowedSignMechanisms = {
    { CKM_ECDSA_SHA1, EVP_sha1 },
    { CKM_ECDSA, NULL },
};


int ECsign(
        const uint8_t *private_key_der,
        size_t privateKeyDERlength,
        const uint8_t *pData,
        size_t dataLen,
        uint8_t *pSignature,
        size_t *pSignatureLengthOut,
        CK_MECHANISM_TYPE mechanism) {
    auto it = allowedSignMechanisms.find(mechanism);
	uint8_t *digest = NULL;
	uint8_t *pSig = NULL;
	unsigned int siglen;
	int ret = -1;
	EVP_MD_CTX *hashctx = NULL;
    if (it == allowedSignMechanisms.end()) goto ECsign_err;

	// Perform SHA1 or not
	if (it->second != NULL) {
		int mdSize = EVP_MD_size(it->second());
		if (mdSize < 0) return -1;
		digest = (uint8_t *) malloc(mdSize);
		if (*pSignatureLengthOut < (size_t) mdSize) goto ECsign_err;
		hashctx = EVP_MD_CTX_new();
		EVP_DigestInit_ex(hashctx, it->second(), NULL);
		EVP_DigestUpdate(hashctx, pData, dataLen);
		EVP_DigestFinal_ex(hashctx, digest, (unsigned int *)&mdSize);
		pData = digest;
		dataLen = mdSize;
	}

	if (NULL == (pSig = ECDSAsign(
		private_key_der, privateKeyDERlength,
        pData, dataLen, &siglen))) goto ECsign_err;
	if (siglen > *pSignatureLengthOut) goto ECsign_err;
	memcpy(pSignature, pSig, siglen);
	*pSignatureLengthOut = siglen;
	ret = 0;
ECsign_err:
	if (digest) free(digest);
	if (hashctx) EVP_MD_CTX_free(hashctx);
	if (pSig) free(pSig);
	return ret;
}
