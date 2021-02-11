#pragma once
#ifndef STUBS_H
#define STUBS_H
#include <stdint.h>

void printhex(const char *s, const uint8_t *buf, unsigned long length);
void printAttr(uint8_t *pAttr, size_t attrLen);

#endif // STUBS_H

