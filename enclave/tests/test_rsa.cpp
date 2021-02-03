#include <stdio.h>

#include <CUnit/Basic.h>

#include "../crypto_engine_t.h"

#include "../Attribute.h"
#include "../AttributeSerial.h"

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "../../cryptoki/pkcs11.h"

extern CK_BBOOL rootKeySet;


CK_BBOOL tr = CK_TRUE;
CK_BBOOL fa = CK_TRUE;
CK_KEY_TYPE keyType = CKK_RSA;
CK_BYTE subject[] = { "Ciphered private RSA key" };
CK_BYTE id[] = { 123 };
CK_BYTE dat[] = "";
CK_ULONG modulus_bits = 2048;


CK_ATTRIBUTE publicRSAKeyTemplate[] = {
    {CKA_KEY_TYPE, &keyType, sizeof keyType},
	{CKA_TOKEN, &tr, sizeof(tr)},
    {CKA_MODULUS_BITS, &modulus_bits, sizeof(modulus_bits)},
	{CKA_ENCRYPT, &tr, sizeof(tr)},
};

CK_ULONG publicRSAKeyTemplateLength = sizeof publicRSAKeyTemplate / sizeof *publicRSAKeyTemplate;;

CK_ATTRIBUTE privateRSAKeyTemplate[] = {
    {CKA_KEY_TYPE, &keyType, sizeof keyType},
	{CKA_TOKEN, &tr, sizeof(tr)},
    {CKA_MODULUS_BITS, &modulus_bits, sizeof(modulus_bits)},
	{CKA_DECRYPT, &tr, sizeof(tr)},
};

CK_ULONG privateRSAKeyTemplateLength = sizeof privateRSAKeyTemplate / sizeof *privateRSAKeyTemplate;;

#define MAX_ATTR_SIZE 2028

//int SGXgenerateKeyPair(uint8_t* RSAPublicKey, size_t publicKeyLength, size_t* publicKeyLengthOut, uint8_t* RSAPrivateKey, size_t privateKeyLength, size_t* privateKeyLengthOut, const uint8_t* pSerialAttr, size_t serialAttrLen);


// int SGXgenerateKeyPair(
//         uint8_t *RSAPublicKey, size_t RSAPublicKeyLength, size_t *RSAPublicKeyLengthOut,
//         uint8_t *RSAPrivateKey, size_t RSAPrivateKeyLength, size_t *RSAPrivateKeyLengthOut,
// 		const uint8_t *pSerialAttr, size_t serialAttrLen);



void test_generateRSAKeyPair(){
	uint8_t pubkey[2048], privkey[2048];
	size_t pubkeyLength, privkeyLength;
    uint8_t *pPublicKeySerializedAttr=NULL;
    size_t publicKeySerializedLen=0;
    size_t publicKeySerializedLenOut = MAX_ATTR_SIZE;
    uint8_t *pPrivSerializedAttr=NULL;
    size_t privSerializedAttrLen=0;
    size_t privSerializedAttrLenOut = MAX_ATTR_SIZE;
    int ret;

    rootKeySet = CK_TRUE;
    pPrivSerializedAttr = attributeSerialize(privateRSAKeyTemplate, privateRSAKeyTemplateLength, &privSerializedAttrLen);
    pPrivSerializedAttr  = (uint8_t *) realloc(pPrivSerializedAttr, MAX_ATTR_SIZE);
    pPublicKeySerializedAttr = attributeSerialize(publicRSAKeyTemplate, publicRSAKeyTemplateLength, &publicKeySerializedLen);
    pPublicKeySerializedAttr  = (uint8_t *) realloc(pPublicKeySerializedAttr, MAX_ATTR_SIZE);
	ret = SGXgenerateKeyPair(pubkey, sizeof pubkey, &pubkeyLength, pPublicKeySerializedAttr, publicKeySerializedLen, &publicKeySerializedLenOut, privkey, sizeof privkey, &privkeyLength, pPrivSerializedAttr, privSerializedAttrLen, &privSerializedAttrLenOut);
	CU_ASSERT_FATAL(0 == ret);
    CU_ASSERT_FATAL(MAX_ATTR_SIZE != publicKeySerializedLenOut);
    CU_ASSERT_FATAL(MAX_ATTR_SIZE != privSerializedAttrLenOut);
    size_t nrAttributes= 0;
    AttributeSerial pubAttr = AttributeSerial(pPublicKeySerializedAttr, publicKeySerializedLen);
    CK_ATTRIBUTE_PTR pPublicAttr = pubAttr.attributes(nrAttributes);
    CU_ASSERT_FATAL(pPublicAttr != NULL);
	ret = SGXgenerateKeyPair(pubkey, 10, &pubkeyLength, pPublicKeySerializedAttr, publicKeySerializedLen, &publicKeySerializedLenOut, privkey, 10, &privkeyLength, pPrivSerializedAttr, privSerializedAttrLen, &privSerializedAttrLenOut);
	CU_ASSERT(ret < 0)
}


// void printAttr(uint8_t *pAttr, size_t attrLen){
//     size_t nrAttributes;
//
//     CK_ATTRIBUTE_PTR attr = attributeDeserialize(pAttr, attrLen, &nrAttributes);
//     for (size_t i=0; i<nrAttributes; i++) {
//         CK_ATTRIBUTE_PTR a = attr + i;
//         printf("Attribute[%04lu] type 0x%08lx, value[%lu] ", i, a->type, a->ulValueLen);
//         for (size_t j=0; j<a->ulValueLen; j++) {
//             printf("%02X ", ((uint8_t *)a->pValue)[j]);
//         }
//         printf("\n");
//     }
//     free(attr);
// }




extern CK_BBOOL rootKeySet;
extern uint8_t rootKey[];
int SGXSetRootKeyShare(int x, const uint8_t *y, size_t y_length, int threshold);

void test_SGXSetRootKeyShare(void)
{
	typedef struct {
		int x;
		const uint8_t y[32];
	} share_t;

	share_t sset[] = {
		{1, {
			0x3c,0x8a,0x69,0xae,0x30,0xe6,0xf3,0x4e,
			0x22,0x43,0x75,0x00,0xe9,0x4a,0x69,0x45,
			0x16,0xb7,0x37,0x93,0x29,0x7e,0x2f,0xfa,
			0x04,0x52,0x72,0x98,0x27,0x16,0x1a,0xf9
		}},
		{2, {
			0x4d,0x44,0x71,0xed,0x8a,0x37,0x5a,0x57,
			0x1a,0xa8,0x1e,0xe8,0x42,0x1d,0x59,0x68,
			0xa4,0xd8,0x86,0x5c,0xef,0x9f,0x6b,0x7a,
			0x24,0x41,0xc3,0x84,0x06,0x8a,0xb9,0x33
		}},
		{3, {
			0x5d,0xfe,0x7a,0x2c,0xe3,0x87,0xc1,0x60,
			0x13,0x0c,0xc8,0xcf,0x9a,0xf0,0x49,0x8c,
			0x32,0xf9,0xd5,0x26,0xb5,0xc0,0xa6,0xfa,
			0x44,0x31,0x14,0x6f,0xe5,0xff,0x57,0x6d
		}},
	};
    const uint8_t secret[32] = {0x2b,0xd0,0x61,0x6e,0xd7,0x96,0x8c,0x45,0x29,0xde,0xcb,0x19,0x90,0x77,0x79,0x21,0x88,0x95,0xe8,0xc9,0x63,0x5c,0xf4,0x79,0xe4,0x63,0x21,0xac,0x47,0xa1,0x7c,0xbf};

	int threshold = 2;

	CU_ASSERT_FATAL(0 == SGXSetRootKeyShare(sset[0].x, sset[0].y, 32, threshold));
	CU_ASSERT_FATAL(rootKeySet == CK_FALSE);
	CU_ASSERT_FATAL(1 == SGXSetRootKeyShare(sset[1].x, sset[1].y, 32, threshold));
	CU_ASSERT_FATAL(rootKeySet == CK_TRUE);
	CU_ASSERT_FATAL(memcmp(secret, rootKey, sizeof secret) == 0);
}


CU_pSuite rsa_suite(void){
    CU_pSuite pSuite = CU_add_suite("RSA", NULL, NULL);
    CU_add_test(pSuite, "generateRSAKeyPair", test_generateRSAKeyPair);
    CU_add_test(pSuite, "SGXSetRootKeyShare", test_SGXSetRootKeyShare);
    return pSuite;
}
