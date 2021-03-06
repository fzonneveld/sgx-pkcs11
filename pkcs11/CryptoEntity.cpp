#include <iostream>
#include <exception>
#include <stdexcept>
#include <sqlite3.h>
#include "CryptoEntity.h"
#include "Attribute.h"

CryptoEntity::CryptoEntity() {
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	sgx_launch_token_t launch_token = { 0 };
	int updated = 0;

	// Step 1: try to retrieve the launch token saved by last transaction
	//         if there is no token, then create a new one.
	auto fp = fopen(this->kTokenFile, "rb");
	if (fp == nullptr) {
		if ((fp = fopen(this->kTokenFile, "wb")) == nullptr) {
			throw std::runtime_error("Failed to create the launch token file.");
		}
	} else {
		// read the token from saved file
		const size_t read_num = fread(launch_token, 1,
			sizeof(sgx_launch_token_t), fp);
		if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
			// if token is invalid, clear the buffer
			memset(&launch_token, 0, sizeof(sgx_launch_token_t));
		}
	}

	// Step 2: call sgx_create_enclave to initialize an enclave instance
	ret = sgx_create_enclave(this->kEnclaveFile, SGX_DEBUG_FLAG, &launch_token, &updated, &this->enclave_id_, NULL);
	if (ret != SGX_SUCCESS) {
        printf("%s:%i ret=0x%x\n", __FILE__, __LINE__, ret);
		throw std::runtime_error("Failed to create enclave.");
	}

	// Step 3: save the launch token if it is updated
	if (updated) {
		fp = freopen(this->kTokenFile, "wb", fp);
		if (fp == nullptr) {
			throw std::runtime_error("Failed to save launch token.");
		}
		const std::size_t write_num = fwrite(launch_token, 1, sizeof(sgx_launch_token_t), fp);
		if (write_num != sizeof(sgx_launch_token_t)) {
			throw std::runtime_error("Failed to save launch token.");
		}
	}
	fclose(fp);
}


#define MAX_KEY_BUF 8192
#define MAX_ATTR_BUF 8192


void CryptoEntity::KeyGeneration(uint8_t **pPublicKey, size_t *pPublicKeyLength, uint8_t **publicSerializedAttr, size_t *pPubAttrLen, uint8_t **pPrivateKey, size_t *pPrivateKeyLength, uint8_t **privSerializedAttr, size_t *pPrivAttrLen) {
	sgx_status_t stat;
    int ret;

    *pPrivateKeyLength = MAX_KEY_BUF;
    *pPublicKeyLength = MAX_KEY_BUF;

    *pPublicKey = (uint8_t *)calloc(*pPublicKeyLength, 1);
    *pPrivateKey = (uint8_t *)calloc(*pPrivateKeyLength, 1);

    if (*pPubAttrLen > MAX_ATTR_BUF || *pPrivAttrLen > MAX_ATTR_BUF) return;

    *publicSerializedAttr = (uint8_t *) realloc(*publicSerializedAttr, MAX_ATTR_BUF);
    size_t pubAttrLen = *pPubAttrLen;
    *pPubAttrLen = MAX_ATTR_BUF;
    *privSerializedAttr = (uint8_t *) realloc(*privSerializedAttr, MAX_ATTR_BUF);
    size_t privAttrLen = *pPrivAttrLen;
    *pPrivAttrLen = MAX_ATTR_BUF;

	stat = SGXgenerateKeyPair(
        this->enclave_id_, &ret,
         *pPublicKey, *pPublicKeyLength, pPublicKeyLength,
         *publicSerializedAttr, pubAttrLen, pPubAttrLen,
         *pPrivateKey, *pPrivateKeyLength,  pPrivateKeyLength,
         *privSerializedAttr, privAttrLen, pPrivAttrLen);
	if (stat != SGX_SUCCESS || ret != 0) {
        printf("%s:%i ret=%lx\n", __FILE__, __LINE__, (unsigned long)ret);
		free(*pPublicKey);
		free(*pPrivateKey);
		throw new std::exception;
	}
	*pPublicKey = (uint8_t *)realloc(*pPublicKey, *pPublicKeyLength);
	*pPrivateKey = (uint8_t *)realloc(*pPrivateKey, *pPrivateKeyLength);

    *publicSerializedAttr = (uint8_t *)realloc(*publicSerializedAttr, *pPubAttrLen);
    *privSerializedAttr = (uint8_t *)realloc(*privSerializedAttr, *pPrivAttrLen);
}

uint8_t *CryptoEntity::Sign(const uint8_t *key, size_t keyLength, uint8_t *pAttribute, size_t attributeLen, const uint8_t *pData, size_t dataLen, size_t *pSignatureLen, CK_MECHANISM_TYPE mechanism){
	sgx_status_t stat;
    int retval;
    uint8_t *sig;
	size_t siglen = 2048;

    sig = (uint8_t *) malloc(siglen);
	*pSignatureLen = siglen;
	stat = SGXSign(
            this->enclave_id_,
            &retval,
			key, keyLength,
            pAttribute, attributeLen,
			pData, dataLen,
		    sig,
			siglen,
            pSignatureLen,
			mechanism);
	if (stat != SGX_SUCCESS || retval != 0) {
		free(sig);
        printf("%s:%i retval=0x%x\n", __FILE__, __LINE__, retval);
		throw std::runtime_error("Sign failed\n");
    }
	return sig;
}

uint8_t* CryptoEntity::RSADecrypt(const uint8_t *key, size_t keyLength, uint8_t *pAttribute, size_t attributeLen, const uint8_t* cipherData, size_t cipherDataLength, size_t* plainLength) {
	sgx_status_t stat;
    int max_rsa_size = 1024;

	uint8_t* plainData = (uint8_t*)malloc(max_rsa_size * sizeof(uint8_t));
    int retval;
	stat = SGXDecrypt(
            this->enclave_id_,
            &retval,
			key, keyLength,
            pAttribute, attributeLen,
			cipherData, cipherDataLength,
			plainData, max_rsa_size, plainLength);
	if (stat != SGX_SUCCESS || retval != 0) {
        printf("%s:%i retval=0x%x\n", __FILE__, __LINE__, retval);
		throw std::runtime_error("Decryption failed\n");
    }
	plainData = (uint8_t *)realloc(plainData, *plainLength);
	return plainData;
}

int CryptoEntity::GenerateRandom(uint8_t *random, size_t random_length) {
	sgx_status_t stat;
    int retval;

	stat = SGXGenerateRandom(
            this->enclave_id_,
            &retval,
			random, random_length);
	if (stat != SGX_SUCCESS || retval != 0) {
		throw std::runtime_error("Generate random failed");
    }
    return 0;
}

size_t CryptoEntity::GetSealedRootKeySize() {
	sgx_status_t stat;
    int retval = -2;
    size_t rootKeySealedLength;

	stat = SGXGetSealedRootKeySize(this->enclave_id_, &retval, &rootKeySealedLength);
	if (stat != SGX_SUCCESS || retval) {
		throw std::runtime_error("Getting root key size failed failed\n");
    }
    return rootKeySealedLength;
}

int CryptoEntity::GenerateRootKey(uint8_t *rootKeySealed, size_t *rootKeySealedLength){
	sgx_status_t stat;
    int retval;
    size_t sealedRootKeySize;
	stat = SGXGetSealedRootKeySize(this->enclave_id_, &retval, &sealedRootKeySize);
	if (stat != SGX_SUCCESS || retval) return 1;
    if (sealedRootKeySize > *rootKeySealedLength) return 2;
	stat = SGXGenerateRootKey(this->enclave_id_, &retval, rootKeySealed, sealedRootKeySize, rootKeySealedLength);
	if (stat != SGX_SUCCESS || retval != 0) return 3;
    return 0;
}

int CryptoEntity::RestoreRootKey(uint8_t *rootKeySealed, size_t rootKeySealedLength){
	sgx_status_t stat;
    int retval;
	stat = SGXSetRootKeySealed(this->enclave_id_, &retval, rootKeySealed, rootKeySealedLength);
	if (stat != SGX_SUCCESS || retval !=0) {
		return 1;
	}
    return 0;
}

CryptoEntity::~CryptoEntity() {
	sgx_destroy_enclave(this->enclave_id_);
}
