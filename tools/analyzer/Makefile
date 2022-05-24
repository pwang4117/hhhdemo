
SOURCES = analyzer.cpp
HEADERS = trace.h utils.h model.h model-offline.h model-online.h model-hash.h

CSOURCES = converter.cpp
CHEADERS = trace.h utils.h model.h

ESOURCES = extractor.cpp
EHEADERS = trace.h utils.h model.h

HSOURCES = hashpipe.cpp
HHEADERS = trace.h utils.h model.h hashpipe.h

TARGET ?= analyzer
NTARGET ?= nanalyzer
CTARGET ?= converter
ETARGET ?= extractor
HTARGET ?= hashpipe

CXX = g++
CXX_FLAGS = -std=c++11 -O3 -Wall -pedantic -g
LD_FLAGS = -lpcap

default: converter analyzer extractor hashpipe

$(TARGET): $(SOURCES) $(HEADERS)
	$(CXX) $(CXX_FLAGS) $(SOURCES) $(LD_FLAGS) -o $@

$(NTARGET): $(SOURCES) $(HEADERS)
	$(CXX) $(CXX_FLAGS) $(SOURCES) $(LD_FLAGS) -o $@

$(CTARGET): $(CSOURCES) $(CHEADERS)
	$(CXX) $(CXX_FLAGS) $(CSOURCES) $(LD_FLAGS) -o $@

$(ETARGET): $(ESOURCES) $(EHEADERS)
	$(CXX) $(CXX_FLAGS) $(ESOURCES) $(LD_FLAGS) -o $@

$(HTARGET): $(HSOURCES) $(HHEADERS)
	$(CXX) $(CXX_FLAGS) $(HSOURCES) $(LD_FLAGS) -o $@

clean:
	rm -rf $(TARGET) $(NTARGET) $(CTARGET) $(ETARGET) $(HTARGET)