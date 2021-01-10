OBJECTS = enclave.o attribute.o ssss.o
TEST_OBJECTS = tst.o stubs.o test_enclave.o test_ssss.o
LDLIBS = -lssl -lcrypto -lstdc++ -lcunit -lpthread

SGX_SDK ?= /opt/intel/sgxsdk
SGX_SSL ?= /opt/intel/sgxssl
# Enclave_Include_Paths := -I../../pkcs11 -I../../cryptoki -I$(SGX_SDK)/include -I$(SGX_SDK)/include/libcxx -I$(SGX_SDK)/include/tlibc -I$(SGX_SSL)/include
# CFLAGS := -Wall -g -I../../pkcs11 -I../../cryptoki -I$(SGX_SDK)/include/libcxx -I${SGX_SDK}/include -I${SGX_SDK}/include/tlibc
# CFLAGS := -Wall -g -I../../pkcs11 -I../../cryptoki -Iinclude/sgxsdk -Iinclude/sgxssl
# CFLAGS := -Wall -g -I../../pkcs11 -I../../cryptoki -Iinclude/sgxsdk
# CFLAGS := -Wall -g -I../../pkcs11 -I../../cryptoki -I${SGX_SDK}/include -Iinclude/sgxssl
CFLAGS := -Wall -g -I../../pkcs11 -I../../cryptoki -I${SGX_SDK}/include -Iinclude/sgxssl
# CFLAGS := -Wall -g $(Enclave_Include_Paths)
# CFLAGS := -Wall -g



tst: $(TEST_OBJECTS) $(OBJECTS)

$(TEST_OBJECTS): %.o: %.cpp
	gcc -c $(CFLAGS) -o $@ $^

$(OBJECTS): %.o: ../%.cpp
	c++ -c $(CFLAGS) -o $@ $^

clean:
	rm -f $(OBJECTS) $(TEST_OBJECTS)

checkvars:
	@echo "SOURCES=$(SOURCES)"
	@echo "OBJECTS=$(OBJECTS)"
