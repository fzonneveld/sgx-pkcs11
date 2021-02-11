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

#include "Attribute.h"

RSA *generateRSA(size_t bits, const uint8_t *exponent, size_t exponentLength);

int generateRSAKeyPair(
        uint8_t **ppRSAPublicKey, size_t *pRSAPublicKeyLength,
        Attribute &pubAttr,
        uint8_t ** ppRSAPrivateKey, size_t *pRSAPrivateKeyLength, Attribute &privAttr);

uint8_t *DecryptRsa(
        uint8_t *private_key_der, size_t privateKeyDERlength,
        const uint8_t *ciphertext, size_t ciphertext_length,
        int padding, int *to_len);

int EncryptRSA(
        const uint8_t* public_key, size_t public_key_length,
        const uint8_t* plaintext, size_t plaintext_length,
        uint8_t* ciphertext, size_t ciphertext_length,
        size_t* cipherTextLength, int padding);

int SignRSA(
        const uint8_t *private_key_der,
        size_t privateKeyDERlength,
        const uint8_t *pData,
        size_t dataLen,
        uint8_t *pSignature,
        size_t *pSignatureLengthOut,
        CK_MECHANISM_TYPE mechanism);
