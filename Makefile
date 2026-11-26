CXX ?= c++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -pthread
LDLIBS ?= -lsqlite3 -pthread
all: dnsense
dnsense: src/main.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)
test: dnsense
	python3 tests/test_dns.py
clean:
	rm -f dnsense
.PHONY: all test clean
