#include <map>
#include <CUnit/Basic.h>
#include "../Attribute.h"
#include "../AttributeSerial.h"

#include "../../cryptoki/pkcs11.h"


CK_BBOOL tr = CK_TRUE;
CK_KEY_TYPE keyType = CKK_RSA;

static void printAttr(uint8_t *pAttr, size_t attrLen){
    size_t nrAttributes;

    AttributeSerial a = AttributeSerial(pAttr, attrLen);
    CK_ATTRIBUTE_PTR attr = a.attributes(nrAttributes);
    for (size_t i=0; i<nrAttributes; i++) {
        CK_ATTRIBUTE_PTR a = attr + i;
        printf("Attribute[%04lu] type 0x%08lx, value[%lu] ", i, a->type, a->ulValueLen);
        for (size_t j=0; j<a->ulValueLen; j++) {
            printf("%02X ", ((uint8_t *)a->pValue)[j]);
        }
        printf("\n");
    }
}


void printhex(const char *s, unsigned char *buf, unsigned long length){
    int i;
    printf("%s", s);
    for (i=0; i< (int)length; i++) {
        if ((i % 16) == 0) printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

void test_Attribute(void){
	CK_ATTRIBUTE aX[] =  {
		{CKA_KEY_TYPE, &keyType, sizeof keyType},
		{CKA_ENCRYPT, &tr, sizeof(tr)},
		{CKA_DECRYPT, &tr, sizeof(tr)},
	};
    size_t asxLen;
    Attribute a = Attribute(aX, sizeof aX / sizeof *aX);
    uint8_t *asX = a.serialize(&asxLen);
    CK_KEY_TYPE *pKeyType;
    uint8_t attrSerialized[58];
    size_t attrSerLen;

    AttributeSerial att = AttributeSerial(asX, asxLen);
    CK_ATTRIBUTE_PTR pAttr;
    pKeyType = att.getType<CK_KEY_TYPE>(CKA_KEY_TYPE);
    CU_ASSERT_FATAL(pKeyType != NULL && *pKeyType == CKK_RSA);
    CK_ULONG keyTypes[] = {CKK_RSA, CKK_EC};
    CU_ASSERT_FATAL((pKeyType = att.checkIn(CKA_KEY_TYPE, keyTypes, sizeof keyTypes / sizeof *keyTypes)) != NULL);
    CU_ASSERT_FATAL(*pKeyType == CKK_RSA);
    att.serialize(attrSerialized, sizeof(attrSerialized), &attrSerLen);
    CU_ASSERT_FATAL(attrSerLen == 58);
    att.merge(aX, asxLen);
}


uint8_t data[] = {
0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x08 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00,
0x03 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x01 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00,
0x01 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x01 ,0x02 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00,
0x00 ,0x01 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x01 ,0x00 ,0x01 ,0x00 ,0x00 ,0x00 ,0x00,
0x00 ,0x00 ,0x08 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00,
0x00 ,0x00 ,0x01 ,0x01 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x19 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00,
0x00 ,0x00 ,0x43 ,0x69 ,0x70 ,0x68 ,0x65 ,0x72 ,0x65 ,0x64 ,0x20 ,0x70 ,0x72 ,0x69 ,0x76 ,0x61,
0x74 ,0x65 ,0x20 ,0x52 ,0x53 ,0x41 ,0x20 ,0x6B ,0x65 ,0x79 ,0x00 ,0x02 ,0x01 ,0x00 ,0x00 ,0x00,
0x00 ,0x00 ,0x00 ,0x01 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x7B ,0x03 ,0x01 ,0x00 ,0x00,
0x00 ,0x00 ,0x00 ,0x00 ,0x01 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x01 ,0x05 ,0x01 ,0x00,
0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x01 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x01 ,0x65 ,0x01,
0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x01 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x01
};

void test_sample_data(){
    AttributeSerial a = AttributeSerial(data, sizeof data);
    printAttr(data, sizeof data);
}

CU_pSuite attribute_suite(void){
    CU_pSuite pSuite = CU_add_suite("PKCS11", NULL, NULL);
    CU_add_test(pSuite, "Attribute", test_Attribute);
    CU_add_test(pSuite, "Attribute", test_sample_data);
    return pSuite;
}
