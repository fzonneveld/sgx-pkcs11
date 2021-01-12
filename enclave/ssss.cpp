#include <map>
#include <openssl/bn.h>


bool unique_points(int *x, size_t x_length) {
    std::map<int, int> m;
    for (size_t i=0; i<x_length; i++) {
        m.insert(std::pair<int, int>(x[i], x[i]));
    }
    return m.size() == x_length;
}

int PI(int  *x_s, size_t s_length, int *offset, int x_idx) {
    int ret = 1;
    for (size_t i=0; i< s_length; i++) {
        if (x_idx >=0  && (size_t) x_idx == i) continue;
        if (offset == NULL)
            ret *= x_s[i];
        else
            ret *= (*offset - x_s[i]);
    }
    return ret;
}


BIGNUM *BN_set_int(int x){
    BIGNUM *num = BN_new();
    BN_set_word(num, (BN_ULONG)abs(x));
    if (x < 0) BN_set_negative(num, 1);
    return num;
}

int lagrange_interpolate(BIGNUM *res, int x, int *x_s, BIGNUM **y_s, size_t s_length, BIGNUM *p)
{
    /*
    Find the y-value for the given x, given n (x, y) points;
    k points will define a polynomial of up to kth order.
    */
    BN_CTX *ctx = BN_CTX_new();
    if (unique_points(x_s, s_length) == false) return -1;

    int *nums = (int *)malloc(sizeof *nums * s_length);
    int *dens = (int *)malloc(sizeof *dens * s_length);
    for (size_t i=0; i<s_length; i++) {
        nums[i] = PI(x_s, s_length, &x, i);
        dens[i] = PI(x_s, s_length, x_s + i, i);
    }
    BIGNUM *den = BN_new();
    BN_RECP_CTX *rctx = BN_RECP_CTX_new();
    BIGNUM *num = BN_new();
    BN_RECP_CTX_set(rctx, p, ctx);
    den = BN_set_int(PI(dens, s_length, NULL, -1));
    for (size_t i=0; i < s_length; i++) {
        BIGNUM *n = BN_set_int(nums[i]);
        BN_mul(n, n, den, ctx);
        BN_mul(n, n, y_s[i], ctx);
        BN_mod(n, n, p, ctx);
        BIGNUM *d = BN_set_int(dens[i]);
        BN_mod_mul_reciprocal(n, n, d, rctx, ctx);
        BN_add(num, num, n);
		BN_free(d);
		BN_free(n);
    }
	BN_mod_mul_reciprocal(res, num, den, rctx, ctx);
	free(den);
    BN_mod(res, res, p, ctx);
    return 0;
}
