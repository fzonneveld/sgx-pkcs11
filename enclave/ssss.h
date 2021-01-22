#pragma once

#include <openssl/bn.h>

int lagrange_interpolate(BIGNUM *res, int x, int *x_s, BIGNUM **y_s, size_t s_length, BIGNUM *p);
