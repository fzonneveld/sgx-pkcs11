#include <map>
#include <CUnit/Basic.h>
#include "../attribute.h"

#include "../../cryptoki/pkcs11.h"


CK_BBOOL tr = CK_TRUE;
CK_KEY_TYPE keyType = CKK_RSA;

void test_serialization(void){
	CK_ATTRIBUTE attributes[] =  {
		{CKA_KEY_TYPE, &keyType, sizeof keyType},
		{CKA_DECRYPT, &tr, sizeof(tr)},
	};
	CK_ULONG dataLen;
	uint8_t *pSer = attributeSerialize(attributes, sizeof attributes / sizeof *attributes, &dataLen);
	CK_ULONG nrAttributes;
	CU_ASSERT_FATAL(pSer != NULL);
	CK_ATTRIBUTE *pAttr = attributeDeserialize(pSer, dataLen, &nrAttributes);
	CU_ASSERT_FATAL(nrAttributes == sizeof attributes / sizeof *attributes);
	for (int i=0; i<nrAttributes; i++) {
		CK_ATTRIBUTE *a=attributes+i, *b=pAttr+i;
		CU_ASSERT_FATAL(attrcmp(a, b) == true);
	}
}

void test_attr2map(void){
	CK_ATTRIBUTE attributes[] =  {
		{CKA_KEY_TYPE, &keyType, sizeof keyType},
		{CKA_DECRYPT, &tr, sizeof(tr)},
	};
	std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> amap;
	amap = attr2map(attributes, sizeof attributes / sizeof *attributes);
	CU_ASSERT_FATAL(amap.size() == sizeof attributes / sizeof *attributes);
	std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>::iterator it;
	it = amap.find(CKA_KEY_TYPE);
	CU_ASSERT_FATAL(it->second == attributes + 0);
	it = amap.find(CKA_DECRYPT);
	CU_ASSERT_FATAL(it->second == attributes + 1);
}

void test_attrMerge(void){
	CK_ATTRIBUTE a1[] =  {
		{CKA_KEY_TYPE, &keyType, sizeof keyType},
		{CKA_ENCRYPT, &tr, sizeof(tr)},
	};
	CK_ATTRIBUTE a2[] =  {
		{CKA_KEY_TYPE, &keyType, sizeof keyType},
		{CKA_DECRYPT, &tr, sizeof(tr)},
	};
	CK_ULONG a3len;
	CK_ATTRIBUTE *a3 = attrMerge(a1, sizeof a1 / sizeof *a1, a2, sizeof a2 / sizeof *a2, &a3len);

	CU_ASSERT_FATAL(a3len == 3);
	CU_ASSERT_FATAL(attrcmp(a1, a3) == true);
	CU_ASSERT_FATAL(attrcmp(a1 + 1, a3 + 1) == true);
}

static void printAttr(uint8_t *pAttr, size_t attrLen){
    size_t nrAttributes;

    CK_ATTRIBUTE_PTR attr = attributeDeserialize(pAttr, attrLen, &nrAttributes);
    for (size_t i=0; i<nrAttributes; i++) {
        CK_ATTRIBUTE_PTR a = attr + i;
        printf("Attribute[%04lu] type 0x%08lx, value[%lu] ", i, a->type, a->ulValueLen);
        for (size_t j=0; j<a->ulValueLen; j++) {
            printf("%02X ", ((uint8_t *)a->pValue)[j]);
        }
        printf("\n");
    }
    free(attr);
}


void test_attrMergeMaps(void){
	CK_ATTRIBUTE a1[] =  {
		{CKA_KEY_TYPE, &keyType, sizeof keyType},
		{CKA_DECRYPT, &tr, sizeof(tr)},
	};
	CK_ATTRIBUTE a2[] =  {
		{CKA_KEY_TYPE, &keyType, sizeof keyType},
		{CKA_ENCRYPT, &tr, sizeof(tr)},
	};
	CK_ATTRIBUTE aX[] =  {
		{CKA_KEY_TYPE, &keyType, sizeof keyType},
		{CKA_ENCRYPT, &tr, sizeof(tr)},
		{CKA_DECRYPT, &tr, sizeof(tr)},
	};
	std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> a1map, a2map, a3map;
	a1map = attr2map(a1, sizeof a1 / sizeof *a1);
	a2map = attr2map(a2, sizeof a2 / sizeof *a2);
    a2map = attrMergeMaps(a2map, a1map);
    CK_ULONG attr2Len;
    CK_ATTRIBUTE_PTR p2Attr = map2attr(a2map, &attr2Len);
    CU_ASSERT_FATAL(a2map.size() == 3);
    CU_ASSERT_FATAL(attr2Len == 3);
    size_t as2Len;
    uint8_t *as2 = attributeSerialize(p2Attr, attr2Len, &as2Len);
    size_t asXLen;
    uint8_t *asX = attributeSerialize(aX, sizeof aX / sizeof *aX, &asXLen);
    CU_ASSERT_FATAL(as2Len == asXLen);
    CU_ASSERT_FATAL(memcmp(as2, asX, as2Len) == 0);
}


void test_Attribute(void){
	CK_ATTRIBUTE aX[] =  {
		{CKA_KEY_TYPE, &keyType, sizeof keyType},
		{CKA_ENCRYPT, &tr, sizeof(tr)},
		{CKA_DECRYPT, &tr, sizeof(tr)},
	};
    size_t asxLen;
    uint8_t *asX = attributeSerialize(aX, sizeof aX / sizeof *aX, &asxLen);
    CK_KEY_TYPE *pKeyType;

    Attribute att = Attribute(asX, asxLen);
    CK_ATTRIBUTE_PTR pAttr;
    CU_ASSERT_FATAL(att.check(CKA_KEY_TYPE, keyType) == true);
    CK_ULONG keyTypes[] = {CKK_RSA, CKK_EC};
    CU_ASSERT_FATAL((pKeyType = att.checkIn(CKA_KEY_TYPE, keyTypes, sizeof keyTypes / sizeof *keyTypes)) != NULL);
    CU_ASSERT_FATAL(*pKeyType == CKK_RSA);
}

CU_pSuite attribute_suite(void){
    printf("%s:%i\n", __FILE__, __LINE__);
    CU_pSuite pSuite = CU_add_suite("PKCS11", NULL, NULL);
    CU_add_test(pSuite, "serialize/deserialize", test_serialization);
    CU_add_test(pSuite, "attr2map", test_attr2map);
    CU_add_test(pSuite, "attrMerge", test_attrMerge);
    CU_add_test(pSuite, "attrMergeMaps", test_attrMergeMaps);
    CU_add_test(pSuite, "Attribute", test_Attribute);
    return pSuite;
}
