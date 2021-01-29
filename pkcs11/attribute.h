#pragma once
#ifndef _ATTRUBUTE_H
#define _ATTRUBUTE_H
#include <map>
#include "pkcs11-interface.h"

CK_ATTRIBUTE_PTR attributeDeserialize(const uint8_t *data, size_t dataLen, CK_ULONG *nrAttributes);
uint8_t *attributeSerialize(CK_ATTRIBUTE *pAttribute, CK_ULONG nrAttributes, size_t *pDataLen);

bool attrcmp(CK_ATTRIBUTE_PTR a, CK_ATTRIBUTE_PTR b);

#define ATTR2MAP(x) attr2map(x, sizeof x / sizeof *x)
std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attr2map(CK_ATTRIBUTE_PTR pAttr, CK_ULONG ulAttrCount);

CK_ATTRIBUTE *map2attr(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> m, CK_ULONG *pAttrLenth);

CK_ATTRIBUTE_PTR getAttr(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attrMap, CK_ATTRIBUTE_TYPE type);

CK_BBOOL getAttrBool(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attrMap, CK_ATTRIBUTE_TYPE type, CK_BBOOL defaultVale, CK_BBOOL *boolValue);

CK_ATTRIBUTE_PTR attrMerge(CK_ATTRIBUTE_PTR pA, CK_ULONG aLen, CK_ATTRIBUTE_PTR  pB, CK_ULONG bLen, CK_ULONG *pAttrLength);
std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>  attrMergeMaps(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> a, std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> b);

CK_RV matchUlAttr(CK_ATTRIBUTE *p, CK_ULONG ul);

bool checkAttr(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attrMap, CK_ATTRIBUTE_TYPE type, uint8_t *pValue, CK_ULONG ulValueLen);

std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attrSerialized2map(const uint8_t *data, size_t dataLen);
int attrMap2serialized(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attrMap, uint8_t  *pSerialAttr, size_t serializedAttrLen, size_t *pSerializedAttrLenOut);



class Attribute{
private:
    CK_ATTRIBUTE_PTR pAttr = NULL;
    CK_ULONG nrAttributes = 0;
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attrMap;
public:
    Attribute(const uint8_t *pSerialized, size_t serializedLen);
    Attribute(CK_ATTRIBUTE_PTR pAttr, size_t nrAttributes);

    CK_ATTRIBUTE_PTR get(CK_ATTRIBUTE_TYPE type);
    void add(CK_ATTRIBUTE_PTR pAtrribute);
    void del(CK_ATTRIBUTE_TYPE type);
    bool check(CK_ATTRIBUTE_TYPE type, CK_ULONG);
    CK_ULONG *checkIn(CK_ATTRIBUTE_TYPE type, CK_ULONG *uls, size_t nrUl);

    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> merge(std::map<CK_ATTRIBUTE_PTR, CK_ATTRIBUTE_PTR> map);
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> map();

    uint8_t *serialize(size_t *pDataLen);
    ~Attribute();
};
#endif
