TEST_DIRS = enclave/tests pkcs11/test

all:
	$(MAKE) -f enclave.mk all
	$(MAKE) -f app.mk all

clean:
	for t in ${TEST_DIRS}; do make -C $$t clean; done
	$(MAKE) -f app.mk clean
	$(MAKE) -f enclave.mk clean
	rm test || true

test_pkcs11:
	make -C pkcs11/test
	pkcs11/test/tst

test_enclave:
	make -C enclave/tests
	enclave/tests/tst

PKCS11_crypto_engine.signed.so:
	$(MAKE) -f enclave.mk all

test: test.cpp
	gcc -g -Wall $< -lstdc++ -ldl -o $@


test_ec: test_ec.cpp
	gcc -g -Wall test.cpp -lstdc++ -ldl -o $@
