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
		{CKA_DECRYPT, &tr, sizeof(tr)},
	};
	CK_ATTRIBUTE a2[] =  {
		{CKA_KEY_TYPE, &keyType, sizeof keyType},
		{CKA_DECRYPT, &tr, sizeof(tr)},
	};
	CK_ULONG a3len;
	CK_ATTRIBUTE *a3 = attrMerge(a1, sizeof a1 / sizeof *a1, a2, sizeof a2 / sizeof *a2, &a3len);

	CU_ASSERT_FATAL(a3len == 2);
	CU_ASSERT_FATAL(attrcmp(a1, a3) == true);
	CU_ASSERT_FATAL(attrcmp(a1 + 1, a3 + 1) == true);
}

CU_pSuite attribute_suite(void){
    printf("%s:%i\n", __FILE__, __LINE__);
    CU_pSuite pSuite = CU_add_suite("PKCS11", NULL, NULL);
    CU_add_test(pSuite, "serialize/deserialize", test_serialization);
    CU_add_test(pSuite, "attr2map", test_attr2map);
    CU_add_test(pSuite, "attrMerge", test_attrMerge);
    return pSuite;
}
