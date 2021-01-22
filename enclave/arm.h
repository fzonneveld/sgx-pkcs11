#pragma once

const uint8_t *getRootKey(size_t *length);

int SetRootKeyShare(int x, const uint8_t *y, size_t y_length, int threshold);

int GetSealedRootKeySize(size_t *rootKeyLength);

int SetRootKeySealed(const uint8_t *root_key_sealed, size_t root_key_len_sealed);

int GetRootKeySealed(uint8_t *root_key_sealed, size_t root_key_len_sealed, size_t *rootKeyLenSealed);

int GenerateRootKey(uint8_t *rootKeySealed, size_t root_key_length, size_t *rootKeyLength);

