all: test
	$(MAKE) -f enclave.mk all
	$(MAKE) -f app.mk all

clean:
	$(MAKE) -f app.mk clean
	$(MAKE) -f enclave.mk clean
	rm test || true

test: test.cpp
	gcc -g -Wall test.cpp -ldl -lstdc++ -o test
