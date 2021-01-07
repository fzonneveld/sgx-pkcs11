TEST_DIRS = enclave/tests pkcs11/test

all: test
	$(MAKE) -f enclave.mk all
	$(MAKE) -f app.mk all
	for t in ${TEST_DIRS}; do make -C $$t; $$t/tst ; done

clean:
	for t in ${TEST_DIRS}; do make -C $$t clean; done
	$(MAKE) -f app.mk clean
	$(MAKE) -f enclave.mk clean
	rm test || true


PKCS11_crypto_engine.signed.so:
	$(MAKE) -f enclave.mk all

test: test.cpp
	gcc -g -Wall test.cpp -lstdc++ -ldl -o $@
