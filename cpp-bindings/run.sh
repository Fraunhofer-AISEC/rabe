#!/bin/bash

set -e

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]:-${(%):-%x}}" )" >/dev/null 2>&1 && pwd )"
PROJ_ROOT="${THIS_DIR}/.."

pushd ${PROJ_ROOT} >> /dev/null
cargo build
popd >> /dev/null

pushd ${THIS_DIR} >> /dev/null

g++ rabe_bindings.cpp -g \
    -o rabe_binding_test \
    -L${PROJ_ROOT}/target/debug \
    -lrabe -Wl,-rpath,${PROJ_ROOT}/target/debug

./rabe_binding_test

popd >> /dev/null
