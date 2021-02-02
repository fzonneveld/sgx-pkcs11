#pragma once

#include "pkcs11-interface.h"
#include "Attribute.h"

class AttributeSerial: public Attribute
{
private:
    CK_ATTRIBUTE_PTR allocated=NULL;
public:
    AttributeSerial(const uint8_t *pSerialized, size_t serializedLen);
    ~AttributeSerial();
};

