#pragma once
#include <openssl/ec.h>
#include "Attribute.h"

int generateECKeyPair(
        uint8_t **ppECPublicKey, size_t *pECPublicKeyLength,
        Attribute &pubAttr,
        uint8_t ** ppECPrivateKey, size_t *pECPrivateKeyLength, Attribute &privAttr);

int ECsign(
        const uint8_t *private_key_der,
        size_t privateKeyDERlength,
        const uint8_t *pData,
        size_t dataLen,
        uint8_t *pSignature,
        size_t *pSignatureLengthOut,
        CK_MECHANISM_TYPE mechanism);
