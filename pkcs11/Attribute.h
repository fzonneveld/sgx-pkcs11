#pragma once
#ifndef _ATTRUBUTE_H
#define _ATTRUBUTE_H
#include <map>
#include "pkcs11-interface.h"

typedef struct {
    CK_ATTRIBUTE_TYPE type;
    CK_ULONG ulValueLen;
    CK_BYTE pValue[0];
} serializedAttr;


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


class Attribute
{
protected:
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attrMap;
public:
    Attribute(){};
    Attribute(CK_ATTRIBUTE_PTR pAttr, size_t nrAttributes);
    Attribute(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attrMap);

    CK_ATTRIBUTE_PTR attributes(CK_ULONG& attributeCnt);
    CK_ATTRIBUTE_PTR get(CK_ATTRIBUTE_TYPE type);
    template<typename T>
    T* getType(CK_ATTRIBUTE_TYPE);
    void add(CK_ATTRIBUTE_PTR pAtrribute);
    void del(CK_ATTRIBUTE_TYPE type);

    template<typename T>
    bool check(CK_ATTRIBUTE_TYPE type, T v);
    // bool check(CK_ATTRIBUTE_TYPE type, CK_ULONG);
    // bool check(CK_ATTRIBUTE_TYPE type, CK_BBOOL value);
    template<typename T>
    T *checkIn(CK_ATTRIBUTE_TYPE type, T *pVal, size_t nr);

    void merge(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> map);
    void merge(CK_ATTRIBUTE_PTR pAttr, size_t nrAttributes);
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> map();

    uint8_t *serialize(size_t *pDataLen);
    int serialize(uint8_t *pData, size_t dataLen, size_t *pDataLen);

    ~Attribute();
};

#endif
