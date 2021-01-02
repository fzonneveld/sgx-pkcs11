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
}

CU_pSuite attribute_suite(void){
    printf("%s:%i\n", __FILE__, __LINE__);
    CU_pSuite pSuite = CU_add_suite("PKCS11", NULL, NULL);
    CU_add_test(pSuite, "serialize/deserialize", test_serialization);
    // CU_add_test(pSuite, "attr2map", test_attr2map);
    return pSuite;
}
