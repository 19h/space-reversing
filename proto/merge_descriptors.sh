#!/bin/bash

protoc \
  -I. \
  --include_imports \
  --descriptor_set_out=merged_descriptor_set.pb \
  $(find . -type f -name '*.proto')
