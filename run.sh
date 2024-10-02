#!/bin/bash
cargo build \
&& g++ test.cpp -g -o test -L$(pwd)/target/debug -lrabe -Wl,-rpath,$(pwd)/target/debug \
&& ./test
