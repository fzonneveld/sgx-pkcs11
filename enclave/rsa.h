#pragma once
#include <map>
#include "openssl/rsa.h"
#include "openssl/bn.h"

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "../cryptoki/pkcs11.h"

RSA *generateRSA(size_t bits, const uint8_t *exponent, size_t exponentLength);

int generateRSAKeyPair(
        uint8_t *RSAPublicKey, size_t RSAPublicKeyLength, size_t *RSAPublicKeyLengthOut,
        std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> &pubAttrMap,
        uint8_t *RSAPrivateKey, size_t RSAPrivateKeyLength, size_t *RSAPrivateKeyLengthOut,
        std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> &privAttrMap);

uint8_t *DecryptRsa(
        uint8_t *private_key_der, size_t privateKeyDERlength,
        const uint8_t *ciphertext, size_t ciphertext_length,
        int padding, int *to_len);

int EncryptRSA(
        const uint8_t* public_key, size_t public_key_length,
        const uint8_t* plaintext, size_t plaintext_length,
        uint8_t* ciphertext, size_t ciphertext_length,
        size_t* cipherTextLength, int padding);
