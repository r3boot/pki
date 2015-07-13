#!/bin/bash

if [ ! -f "./ci/common.sh" ]; then
    error "Invalid PWD"
fi

source ./ci/common.sh

# Perform code checking and analysis
info "Running pylint"
pylint -f parseable \
    ./pkilib/*.py \
    ./pkilib/ca/*.py \
    ./scripts/* \
    ./scripts/vms/vmsbundle \
    ./ci/*.py \
    > pylint.log
