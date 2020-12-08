#pragma once
#ifndef POLITO_CSS_ESIGNER_H_
#define POLITO_CSS_ESIGNER_H_

#include <sgx_urts.h>
#include <string>
#include "crypto_engine_u.h"
#include "shared_values.h"


class CryptoEntity {
private:
#ifdef _WIN32
	const char* kEnclaveFile = "PKCS11_crypto_engine.signed.dll";
#else
	const char* kEnclaveFile = "PKCS11_crypto_engine.signed.so";
#endif
	const char* kTokenFile = "token";
	sgx_enclave_id_t enclave_id_;
	struct {
		uint8_t *value;
		size_t length;
    } initializedKey;
public:
	CryptoEntity();
    void RSAKeyGeneration(uint8_t **pPublicKey, size_t *pPublicKeyLength, uint8_t **pPrivateKey, size_t *pPrivateKeyLength, uint8_t *serialAttr, size_t serialAttrLen, size_t bitLen);
	void RSAInitEncrypt(uint8_t* key, size_t length);
	uint8_t* RSAEncrypt(const uint8_t* plainData, size_t plainDataLength, size_t* cipherLength);
	void RSAInitDecrypt(uint8_t* key, size_t length);
	uint8_t* RSADecrypt(const uint8_t* cipherData, size_t cipherDataLength, size_t* plainLength);
    size_t GetSealedRootKeySize();
    int GenerateRootKey(uint8_t *rootKeySealed, size_t *rootKeySealedLength);
    int RestoreRootKey(uint8_t *rootKeySealed, size_t rootKeySealedLength);
	~CryptoEntity();
};

#endif  // POLITO_CSS_ESIGNER_H_
