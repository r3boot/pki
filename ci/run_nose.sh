#!/bin/bash

if [ ! -f "./ci/common.sh" ]; then
    error "Invalid PWD"
fi

source ./ci/common.sh

# Setup temporary configuration files
mkdir -p ./workspace/unittest
cp -Rp ./config ./workspace/unittest/
cp -Rp ./templates ./workspace/

sed -i \
    -e 's,/etc/pki,./workspace,g' \
    -e 's,as65342.net,example.com,g' \
    -e 's,as65342,test,g' \
    -e 's,AS65342,Test,g' \
    -e 's,Utrecht,Province,g' \
    -e 's,Amersfoort,City,g' \
    -e 's,PKI services,Organizational Unit,g' \
    ./workspace/unittest/config/pki.yml

# Perform unit testing and code coverage
info "Running unit and coverage tests"
nosetests -v \
    --with-coverage \
    --cover-erase \
    --cover-package=pkilib \
    --cover-html \
    --cover-branches \
    --cover-inclusive \
    pkilib/tests/*.py
