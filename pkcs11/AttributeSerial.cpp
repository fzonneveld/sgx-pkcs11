#include <stdint.h>
#include "AttributeSerial.h"

AttributeSerial :: AttributeSerial(const uint8_t *pSerialized, size_t serializedLen): Attribute() {
    int nrAttributes = 0;
    size_t attrLen;
    CK_ATTRIBUTE_PTR pAttr=NULL;
    std::map<CK_ATTRIBUTE_TYPE, serializedAttr *> serAttrMap;

    for (; serializedLen > 0;) {
        serializedAttr *pSerAttr = (serializedAttr *)pSerialized;
        serAttrMap[pSerAttr->type] = pSerAttr;
        attrLen = sizeof *pSerAttr + pSerAttr->ulValueLen;
        if (pSerAttr->ulValueLen > serializedLen || attrLen > serializedLen)
            throw std::runtime_error("Invalid attributes");
        pSerialized += attrLen;
        serializedLen -= attrLen;
        nrAttributes++;
    }
    this->allocated = (CK_ATTRIBUTE_PTR) calloc(nrAttributes * sizeof *this->allocated, 1);
    int idx=0;
    for (auto it=serAttrMap.begin(); it != serAttrMap.end(); it++) {
        serializedAttr *pSerAttr = it->second;
        pAttr = this->allocated + idx;
        pAttr->type = pSerAttr->type;
        pAttr->ulValueLen = pSerAttr->ulValueLen;
        pAttr->pValue = pSerAttr->pValue;
        this->attrMap[pAttr->type] = pAttr;
        idx++;
    }

    // Insert ordered, if allocated can free with the first element...
    // for (; serializedLen > 0;) {
    //     serializedAttr *pSerAttr = (serializedAttr *)pSerialized;
    //     nrAttributes +=1;
    //     this->allocated = (CK_ATTRIBUTE_PTR) realloc(
    //         this->allocated, nrAttributes * sizeof *this->allocated);
    //     pAttr = this->allocated + (nrAttributes -1);
    //     pAttr->type = pSerAttr->type;
    //     pAttr->ulValueLen = pSerAttr->ulValueLen;
    //     pAttr->pValue = pSerAttr->pValue;
    //     attrLen = sizeof *pSerAttr + pSerAttr->ulValueLen;
    //     if (pSerAttr->ulValueLen > serializedLen || attrLen > serializedLen)
    //         throw std::runtime_error("Invalid attributes");
    // }
    // // Because of the realloc we need a second loop
    // for (int i=0; i<nrAttributes; i++) {
    //     CK_ATTRIBUTE_PTR p = this->allocated + i;

    //     this->attrMap[p->type] = p;
    // }

}

AttributeSerial::~AttributeSerial() {
    if (this->allocated) free(this->allocated);
}
