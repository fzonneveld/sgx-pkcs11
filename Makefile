# TEST_DIRS = enclave/tests pkcs11/test
TEST_DIRS = enclave/tests 

all: test
	for t in ${TEST_DIRS}; do make -C $$t; $$t/tst ; done
	$(MAKE) -f enclave.mk all
	$(MAKE) -f app.mk all

clean:
	for t in ${TEST_DIRS}; do make -C $$t clean; done
	$(MAKE) -f app.mk clean
	$(MAKE) -f enclave.mk clean
	rm test || true


test: test.cpp
	gcc -g -Wall test.cpp -lstdc++ -ldl -o $@
