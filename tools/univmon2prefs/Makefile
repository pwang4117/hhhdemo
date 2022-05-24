
SOURCES = univmon2prefs.cpp
HEADERS = ../analyzer/utils.h

TARGET ?= univmon2prefs

CXX = g++
CXX_FLAGS = -std=c++11 -O3 -Wall -pedantic -g
LD_FLAGS =

default: univmon2prefs

$(TARGET): $(SOURCES) $(HEADERS)
	$(CXX) $(CXX_FLAGS) $(SOURCES) $(LD_FLAGS) -o $@

clean:
	rm -rf $(TARGET)

