OBJECTS = enclave.o
TEST_OBJECTS = tst.o stubs.o
LDLIBS = -lssl -lcrypto -lcunit

SGX_SDK ?= /opt/intel/sgxsdk
SGX_SSL ?= /opt/intel/sgxssl
CFLAGS := -Wall -g -I../../pkcs11 -I../../cryptoki -I${SGX_SDK}/include -I${SGX_SSL}/include


tst: $(OBJECTS) $(TEST_OBJECTS)

$(TEST_OBJECTS): %.o: %.cpp
	$(CC) -c $(CFLAGS) -o $@ $^ 

$(OBJECTS): %.o: ../%.cpp
	$(CC) -c $(CFLAGS) -o $@ $^ 

clean:
	rm -f $(OBJECTS) $(TEST_OBJECTS)

checkvars:
	@echo "SOURCES=$(SOURCES)"
	@echo "OBJECTS=$(OBJECTS)"
