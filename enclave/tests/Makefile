OBJECTS = enclave.o Attribute.o AttributeSerial.o ssss.o rsa.o ec.o arm.o
TEST_OBJECTS = tst.o test_enclave.o stubs.o test_rsa.o test_ssss.o test_ec.o
LDLIBS = -lssl -lcrypto -lstdc++ -lcunit -lpthread

SGX_SDK ?= /opt/intel/sgxsdk
SGX_SSL ?= /opt/intel/sgxssl
CFLAGS := -Wall -g -I../../pkcs11 -I../../cryptoki -I${SGX_SDK}/include -Iinclude/sgxssl



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
