#include <stdio.h>
#include <map>
#include <openssl/crypto.h>
#include "Attribute.h"
#include <stdio.h>


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

