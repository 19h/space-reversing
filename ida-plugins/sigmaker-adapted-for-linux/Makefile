# IDA SigMaker - Linux Makefile
# Build configuration for IDA Pro plugin on Linux

# Configuration
IDA_SDK = $(HOME)/idasdk91
TARGET_DIR = .
PLUGIN_NAME = sigmaker64
PLUGIN_NAME_32 = sigmaker

# Compiler settings
CXX = g++
CXXFLAGS = -std=c++23 -fPIC -O2 -Wall -Wextra
DEFINES = -D__LINUX__ -D__EA64__ -D__X64__ -DUSE_STANDARD_FILE_FUNCTIONS

# Include paths
INCLUDES = -I$(IDA_SDK)/include -Isrc

# Library paths and libraries
LIBPATHS = -L$(IDA_SDK)/lib/x64_linux_gcc_64
LIBS = -lida -ldl

# Source files
SOURCES = src/Main.cpp src/Plugin.cpp src/SignatureUtils.cpp src/Utils.cpp

# Object files
OBJECTS = src/Main.o src/Plugin.o src/SignatureUtils.o src/Utils.o

# 64-bit plugin target
$(PLUGIN_NAME).so: $(OBJECTS)
	$(CXX) -shared $(CXXFLAGS) -o $@ $^ $(LIBPATHS) $(LIBS)

# 32-bit plugin target (if needed)
$(PLUGIN_NAME_32).so: CXXFLAGS += -m32
$(PLUGIN_NAME_32).so: LIBPATHS = -L$(IDA_SDK)/lib/x86_linux_gcc_32
$(PLUGIN_NAME_32).so: DEFINES = -D__LINUX__ -DUSE_STANDARD_FILE_FUNCTIONS
$(PLUGIN_NAME_32).so: $(OBJECTS)
	$(CXX) -shared $(CXXFLAGS) -o $@ $^ $(LIBPATHS) $(LIBS)

# Compile source files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(DEFINES) $(INCLUDES) -c $< -o $@

# Phony targets
.PHONY: clean all install 64bit 32bit

# Default target
all: $(PLUGIN_NAME).so

# Individual targets
64bit: $(PLUGIN_NAME).so
32bit: $(PLUGIN_NAME_32).so

# Clean
clean:
	rm -f $(OBJECTS) $(PLUGIN_NAME).so $(PLUGIN_NAME_32).so

# Install (copy to IDA plugins directory - adjust path as needed)
install: $(PLUGIN_NAME).so
	@echo "Copy $(PLUGIN_NAME).so to your IDA Pro plugins directory"
	@echo "Example: cp $(PLUGIN_NAME).so /path/to/ida/plugins/"

# Debug info
info:
	@echo "IDA SDK: $(IDA_SDK)"
	@echo "Sources: $(SOURCES)"
	@echo "Objects: $(OBJECTS)"
	@echo "CXX Flags: $(CXXFLAGS)"
	@echo "Includes: $(INCLUDES)"
	@echo "Lib Paths: $(LIBPATHS)"
