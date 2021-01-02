#pragma once
#ifndef _STUBS_H
#define _STUBS_H
#include <sgx_urts.h>
 
#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t SGXgenerateRSAKeyPair(sgx_enclave_id_t eid, int* retval, uint8_t* RSAPublicKey, size_t publicKeyLength, size_t* publicKeyLengthOut, uint8_t* RSAPrivateKey, size_t privateKeyLength, size_t* privateKeyLengthOut, const uint8_t* pSerialAttr, size_t serialAttrLen, const unsigned char* exponent, size_t exponentLength, size_t bitLen);
sgx_status_t SGXEncryptRSA(sgx_enclave_id_t eid, int* retval, const uint8_t* public_key, size_t public_key_length, const uint8_t* plaintext, size_t plaintext_length, uint8_t* ciphertext, size_t ciphertext_length, size_t* cipherTextLength);
sgx_status_t SGXDecryptRSA(sgx_enclave_id_t eid, int* retval, const unsigned char* private_key_ciphered, size_t private_key_ciphered_length, const unsigned char* attributes, size_t attributes_length, const unsigned char* ciphertext, size_t ciphertext_length, unsigned char* plaintext, size_t plaintext_length, size_t* plainTextLength);
sgx_status_t SGXGenerateRandom(sgx_enclave_id_t eid, int* retval, unsigned char* random, size_t random_length);
sgx_status_t SGXGenerateRootKey(sgx_enclave_id_t eid, int* retval, uint8_t* rootkeySealed, size_t root_key_length, size_t* rootKeyLength);
sgx_status_t SGXGetSealedRootKeySize(sgx_enclave_id_t eid, size_t* retval);
sgx_status_t SGXSetRootKeySealed(sgx_enclave_id_t eid, int* retval, const uint8_t* root_key_sealed, size_t root_key_len_sealed);
sgx_status_t SGXGetRootKeySealed(sgx_enclave_id_t eid, int* retval, uint8_t* root_key_sealed, size_t root_key_len_sealed, size_t* rootKeyLenSealed);

#ifdef __cplusplus
}
#endif

#endif
