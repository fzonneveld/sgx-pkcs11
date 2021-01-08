#include <stdio.h>
#include <vector>
#include <CUnit/Basic.h>

#include <openssl/bn.h>

bool unique_points(int *x, size_t x_length);

void test_unique_points(void) {
    int points[] = {1,2,3,4,5};
    CU_ASSERT_FATAL(unique_points(points, sizeof points / sizeof *points) == true);
    int points_false[] = {1,2,3,4,5, 5};
    CU_ASSERT_FATAL(unique_points(points_false, sizeof points_false / sizeof *points_false) == false);
}

int PI(int  *x_s, size_t s_length, int *offset, int x_idx);

void test_PI(void) {
    int x_s[] = {1,2,-3};
    CU_ASSERT_FATAL(PI(x_s, sizeof x_s / sizeof *x_s, NULL, -1) == -6);
}

int lagrange_interpolate(BIGNUM *res, int x, int *x_s, BIGNUM **y_s, size_t s_length, BIGNUM *p);

/*
Secret:                                                      2bd0616ed7968c4529decb19907779218895e8c9635cf479e46321ac47a17cbf
Shares:
  {},{} 1 3c8a69ae30e6f34e22437500e94a694516b73793297e2ffa0452729827161af9
  {},{} 2 4d4471ed8a375a571aa81ee8421d5968a4d8865cef9f6b7a2441c384068ab933
  {},{} 3 5dfe7a2ce387c160130cc8cf9af0498c32f9d526b5c0a6fa4431146fe5ff576d
Secret recovered from minimum subset of shares:              2bd0616ed7968c4529decb19907779218895e8c9635cf479e46321ac47a17cbf
Secret recovered from a different minimum subset of shares:  2bd0616ed7968c4529decb19907779218895e8c9635cf479e46321ac47a17cbf

*/

typedef struct {
	int x_s;
	const char *y_s;
} share_t;

share_t share_set1[] = {
	{1, "3c8a69ae30e6f34e22437500e94a694516b73793297e2ffa0452729827161af9"},
	{2, "4d4471ed8a375a571aa81ee8421d5968a4d8865cef9f6b7a2441c384068ab933"},
	{3, "5dfe7a2ce387c160130cc8cf9af0498c32f9d526b5c0a6fa4431146fe5ff576d"},
};

typedef struct {
	int nr_shares;
	int threshold;
	const char *secret;
    const char *prime;
	share_t *shares;
} share_test_set_t;

share_test_set_t set1 = {
	3, // nr_shares
    2, // threshold
	"2bd0616ed7968c4529decb19907779218895e8c9635cf479e46321ac47a17cbf", // secret
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43", // prime
	share_set1
};

share_t share_set2[] = {
	{1,"00098106edea9e7dd42c1dd000bc2b3144ca15950f4cefefbe353ed30e4e69b4"},
	{2,"1e6d8bf3f2841f9c6a4908a4775ee1f468ac70da5fa4de393bb7fe116668629e"},
	{3,"48c91c8ca279ef21728842a6d37d28c55dd902e7b3ed5d2afca7a558adad8432"},
	{4,"7f1c32d0fdcc0d0cece9cbd71516ffa4244fcbbd0c266cc5010434a8e41dce70"},
	{5,"c166cec1047a795ed96da4353c2c6690bc10cb5a68500d0748cdac0209b94158"},
};


share_test_set_t set2 = {
	5, // nr_shares
    3, // threshold
	"ed9cfbc594ad6bc5b03182296f95047bf231f117c2e5924e841f679da55f98b7", // secret
	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43", // prime
	share_set2
};


void test_lagrange_interpolate(void) {
	std::vector<share_test_set_t> tests = {set1, set2};
	for (auto set=tests.begin(); set!=tests.end(); set++) {

		int *x_s = (int *) malloc(sizeof *x_s * set1.threshold);
		for (int i=0; i<set1.threshold; i++) {
			x_s[i] = set1.shares[i].x_s;
		}

		BIGNUM **y_s =(BIGNUM **)  malloc(sizeof *y_s * set1.nr_shares);

		for (int i=0; i<set1.nr_shares; i++) {
			y_s[i] = BN_new();
			BN_hex2bn(&y_s[i], set1.shares[i].y_s);
		}

		BIGNUM *p = NULL;
		BIGNUM *s = NULL;;
		BN_hex2bn(&p, set1.prime);
		BN_hex2bn(&s, set1.secret);
		BIGNUM *res = BN_new();
		CU_ASSERT_FATAL(lagrange_interpolate(res, 0, x_s, y_s, set1.threshold, p) == 0);
		CU_ASSERT_FATAL(BN_cmp(res, s) == 0);
	}
}

CU_pSuite ssss_suite(void){
    CU_pSuite pSuite = CU_add_suite("SSSS", NULL, NULL);
    CU_add_test(pSuite, "unique_points", test_unique_points);
    CU_add_test(pSuite, "PI", test_PI);
    CU_add_test(pSuite, "lagrange_interpolate", test_lagrange_interpolate);
    return pSuite;
}
