#include <stdio.h>
#include <map>
#include <openssl/crypto.h>
#include "Attribute.h"
#include <stdio.h>


CK_ATTRIBUTE_PTR attributeDeserialize(const uint8_t *data, size_t dataLen, CK_ULONG *nrAttributes){
    CK_ATTRIBUTE_PTR ret = NULL;
    *nrAttributes = 0;
    while (dataLen != 0) {
        serializedAttr *pSerAttr = (serializedAttr *)data;
        if (dataLen < sizeof *pSerAttr) goto error_exit;
        if (pSerAttr->ulValueLen == 0 || dataLen < (sizeof *pSerAttr + pSerAttr->ulValueLen)) goto error_exit;

        ret = (CK_ATTRIBUTE_PTR)realloc(ret, sizeof (*ret) * (*nrAttributes + 1));
        CK_ATTRIBUTE_PTR pAttr = ret + *nrAttributes;
        pAttr->type = pSerAttr->type;
        pAttr->ulValueLen = pSerAttr->ulValueLen;
        if ((pAttr->pValue = malloc(pSerAttr->ulValueLen)) == NULL) goto error_exit;
        memcpy(pAttr->pValue, pSerAttr->pValue, pSerAttr->ulValueLen);
        dataLen -= (sizeof *pSerAttr + pSerAttr->ulValueLen);
        data = data + (sizeof *pSerAttr + pSerAttr->ulValueLen);
        *nrAttributes = *nrAttributes + 1;
    }
    return ret;
error_exit:
    if (ret) {
        CK_ULONG i;
        for (i=0; i< *nrAttributes; i++) if (ret[i].pValue) free(ret[i].pValue);
        free(ret);
    }
    return NULL;
}

uint8_t *attributeSerialize(CK_ATTRIBUTE *pAttribute, CK_ULONG nrAttributes, size_t *pDataLen){
    uint8_t *ret = NULL;
    *pDataLen = 0;
    // Enforce the order of the map, which is by type
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attrmap = attr2map(pAttribute, nrAttributes);
	std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>::iterator it;
    for (it=attrmap.begin(); it != attrmap.end(); it++) {
        CK_ATTRIBUTE_PTR pAttr=it->second;;
        ret = (uint8_t *) realloc(ret, *pDataLen + pAttr->ulValueLen + sizeof pAttr->type + sizeof pAttr->ulValueLen);
        *((CK_ATTRIBUTE_TYPE *)(ret + *pDataLen))= pAttr->type;
        *((CK_ULONG *)(ret + *pDataLen + sizeof pAttr->type))= pAttr->ulValueLen;
        *pDataLen = *pDataLen + sizeof pAttr->type + sizeof pAttr->ulValueLen;
        memcpy(ret + (*pDataLen), pAttr->pValue, pAttr->ulValueLen);
        nrAttributes -= 1;
        *pDataLen = *pDataLen + pAttr->ulValueLen;
    }
    return ret;
}

std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attr2map(CK_ATTRIBUTE_PTR pAttr, CK_ULONG ulAttrCount) {
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attrMap;
    do {
        attrMap[pAttr->type] = pAttr;
        pAttr++;
    } while (--ulAttrCount != 0);
    return attrMap;
}


CK_ATTRIBUTE_PTR getAttr(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attrMap, CK_ATTRIBUTE_TYPE type) {
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>::iterator it;
    it = attrMap.find(type);
	return it == attrMap.end() ? NULL : it->second;
}

CK_RV matchUlAttr(CK_ATTRIBUTE *p, CK_ULONG ul) {
    if (p) {
        if (sizeof(CK_ULONG) != p->ulValueLen) return CKR_ATTRIBUTE_VALUE_INVALID;
        if (*((CK_ULONG *)p->pValue) != ul) return CKR_TEMPLATE_INCONSISTENT;
    }
    return CKR_OK;
}

CK_BBOOL getAttrBool(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> attrMap, CK_ATTRIBUTE_TYPE type, CK_BBOOL defaultVale, CK_BBOOL *boolValue) {
    CK_ATTRIBUTE *pAttr;
    if ((pAttr = getAttr(attrMap, type)) == NULL) {
        *boolValue = defaultVale;
    } else {
        if (pAttr->ulValueLen != sizeof(CK_BBOOL)) return CKR_ATTRIBUTE_VALUE_INVALID;
        *boolValue = *((CK_BBOOL *)pAttr->pValue);
    }
    return CKR_OK;
}

CK_ATTRIBUTE *map2attr(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> m, CK_ULONG *pAttrLenth){
	int i;
	std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>::iterator it;
	CK_ATTRIBUTE *pRes;
    if ((pRes = (CK_ATTRIBUTE *)malloc(sizeof *pRes * m.size())) == NULL) {
		return NULL;
	};
	for (i=0, it=m.begin(); it != m.end(); it++, i++){
		CK_ATTRIBUTE_PTR pDest = pRes + i;
		CK_ATTRIBUTE_PTR pSrc = it->second;
		if ((pDest->pValue = malloc(pSrc->ulValueLen)) == NULL) {
			return NULL;
		}
		memcpy(pDest->pValue, pSrc->pValue, pSrc->ulValueLen);
		pDest->ulValueLen = pSrc->ulValueLen;
		pDest->type = pSrc->type;
	}
	*pAttrLenth = (CK_ULONG)i;
	return pRes;
}

std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR>  attrMergeMaps(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> a, std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> b){
	a.insert(b.begin(), b.end());
    return a;
}


CK_ATTRIBUTE_PTR attrMerge(
		CK_ATTRIBUTE_PTR pA, CK_ULONG aLen, CK_ATTRIBUTE_PTR  pB, CK_ULONG bLen, CK_ULONG *pAttrLength) {
	std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> a = attr2map(pA, aLen);
	std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> b = attr2map(pB, bLen);

	a.insert(b.begin(), b.end());
	CK_ATTRIBUTE_PTR ret=map2attr(a, pAttrLength);
	a.clear();
	b.clear();
	return ret;
}

bool attrcmp(CK_ATTRIBUTE_PTR a, CK_ATTRIBUTE_PTR b){
	if (a->type != b->type) return false;
	if (a->ulValueLen != b->ulValueLen) return false;
	return memcmp(a->pValue, b->pValue, a->ulValueLen) == 0 ? true : false;
}


Attribute::Attribute(CK_ATTRIBUTE_PTR pAttr, size_t nrAttributes){
    do {
        this->attrMap[pAttr->type] = pAttr;
        pAttr++;
    } while (--nrAttributes != 0);
}

Attribute::Attribute(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> aMap) {
    this->attrMap = aMap;
}

uint8_t *Attribute::serialize(size_t *pDataLen){
    uint8_t *pData = NULL;
    size_t attrSize;

    *pDataLen = 0;
    for (auto  it=attrMap.begin(); it != attrMap.end(); it++) {
        CK_ATTRIBUTE_PTR pAttr=it->second;;
        attrSize = pAttr->ulValueLen + sizeof pAttr->type + sizeof pAttr->ulValueLen;
        if ((pData = (uint8_t *) realloc(pData, *pDataLen + attrSize)) == NULL)
            return NULL;
        serializedAttr *a = (serializedAttr *) (pData + *pDataLen);
        a->type = pAttr->type;
        a->ulValueLen = pAttr->ulValueLen;
        memcpy(a->pValue, pAttr->pValue, pAttr->ulValueLen);
        *pDataLen = *pDataLen + attrSize;
    }
    return pData;
}

int Attribute::serialize(uint8_t *pSerialAttr, size_t dataLen, size_t *pDataLen){
    uint8_t *pData;

    if ((pData = this->serialize(pDataLen)) == NULL) {
        return -1;
    }
    if (*pDataLen > dataLen) {
        free(pData);
        return -1;
    }
    memcpy(pSerialAttr, pData, *pDataLen);
    free(pData);
	return 0;
}

CK_ATTRIBUTE_PTR Attribute::attributes(CK_ULONG& attributeCnt){
    attributeCnt = this->attrMap.size();
    return this->attrMap.begin()->second;
}

CK_ATTRIBUTE_PTR Attribute::get(CK_ATTRIBUTE_TYPE type){
    auto it = this->attrMap.find(type);
    if (it == this->attrMap.end()) return NULL;
    return it->second;
}



template<typename T>
T* Attribute::getType(CK_ATTRIBUTE_TYPE type) {
    CK_ATTRIBUTE_PTR p = this->get(type);
    if (p == NULL) return NULL;
    if (sizeof(T) != p->ulValueLen) return NULL;
    return (T *)p->pValue;
}

template CK_BBOOL* Attribute::getType<CK_BBOOL>(CK_ATTRIBUTE_TYPE type);
template CK_ULONG* Attribute::getType<CK_ULONG>(CK_ATTRIBUTE_TYPE type);

template<typename T>
bool Attribute::check(CK_ATTRIBUTE_TYPE type, T v) {
    CK_ATTRIBUTE_PTR p = this->get(type);
    if (p == NULL) return false;
    if (sizeof(T) != p->ulValueLen) return false;
    if (*((T *)p->pValue) != v) return false;
    return true;
}

// Instantiate types for check here....
template bool Attribute::check<CK_ULONG>(CK_ATTRIBUTE_TYPE type, CK_ULONG v);
template bool Attribute::check<CK_BBOOL>(CK_ATTRIBUTE_TYPE type, CK_BBOOL v);


template<typename T>
T *Attribute::checkIn(CK_ATTRIBUTE_TYPE type, T *pVal, size_t nr) {
    CK_ATTRIBUTE_PTR p = this->get(type);
    if (p == NULL) return NULL;
    if (sizeof(*pVal) != p->ulValueLen) return NULL;
    for (CK_ULONG i=0; i<nr; i++) {
        if (*((T *)p->pValue) == pVal[i]) return (T *)p->pValue;
    }
    return NULL;
}

template CK_ULONG *Attribute::checkIn<CK_ULONG>(CK_ATTRIBUTE_TYPE type, CK_ULONG *pVal, size_t nr);


void  Attribute::merge(std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> b){
	this->attrMap.insert(b.begin(), b.end());
}

void  Attribute::merge(CK_ATTRIBUTE_PTR pAttr, size_t nrAttributes){
    Attribute a = Attribute(pAttr, nrAttributes);
    std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> m = a.map();
	this->attrMap.insert(m.begin(), m.end());
}

std::map<CK_ATTRIBUTE_TYPE, CK_ATTRIBUTE_PTR> Attribute::map() {
    return this->attrMap;
}

Attribute::~Attribute() {
}

