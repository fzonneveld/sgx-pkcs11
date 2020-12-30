#pragma once
#ifndef _ATTRUBUTE_H
#define _ATTRUBUTE_H
#include <map>
#include "pkcs11-interface.h"

CK_ATTRIBUTE_PTR attributeDeserialize(const uint8_t *data, size_t dataLen, CK_ULONG *nrAttributes);
uint8_t *attributeSerialize(CK_ATTRIBUTE *pAttribute, CK_ULONG nrAttributes, size_t *pDataLen);

std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attr2map(CK_ATTRIBUTE_PTR pAttr, CK_ULONG ulAttrCount);
CK_ATTRIBUTE *map2attr(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> m, CK_ULONG *pAttrLenth);

CK_ATTRIBUTE_PTR getAttr(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attrMap, CK_ATTRIBUTE_TYPE type);

CK_BBOOL getAttrBool(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attrMap, CK_ATTRIBUTE_TYPE type, CK_BBOOL defaultVale, CK_BBOOL *boolValue);

CK_ATTRIBUTE_PTR attrMerge(CK_ATTRIBUTE_PTR pA, CK_ULONG aLen, CK_ATTRIBUTE_PTR  pB, CK_ULONG bLen, CK_ULONG *pAttrLength);

CK_RV matchUlAttr(CK_ATTRIBUTE *p, CK_ULONG ul);

bool checkAttr(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attrMap, CK_ATTRIBUTE_TYPE type, uint8_t *pValue, CK_ULONG ulValueLen);
#endif
