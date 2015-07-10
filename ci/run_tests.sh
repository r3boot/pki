#!/bin/bash

WORKSPACE="${PWD}/workspace"
CONFIG="${PWD}/config/pki.yml"
LOGGING="${PWD}/config/logging.yml"

INITPKI="${PWD}/scripts/initpki"

CA_PASS="$(echo $RANDOM | sha1sum | awk '{print $1}')"

function info {
    echo "[+] ${@}"
}

function error {
    echo "[E] ${@}"
    exit 1
}

if [ ! -f "./ci/run_tests.sh" ]; then
    error "Invalid PWD"
fi

# Perform code checking and analysis
info "Running pyling"
pylint -f parseable ./scripts/* ./ci/*.py ./scripts/vms/vmsbundle > pylint.log

# Perform unit testing and code coverage
info "Running unit and coverage tests"
pushd ./tests >/dev/null 2>&1
make tests
popd >/dev/null 2>&1

# Then, perform a full application test
if [ -d "${WORKSPACE}" ]; then
    info "Cleaning up ${WORKSPACE}"
    rm -rf "${WORKSPACE}"
fi

info "Creating ${WORKSPACE}"
mkdir -p "${WORKSPACE}"
mkdir -p "${WORKSPACE}/html/crl"

# Initialize the PKI
#${INITPKI} -d -f ${CONFIG} -l ${LOGGING} -w ${WORKSPACE} \
#    --root-pw ${CA_PASS} --inter-pw ${CA_PASS}

# Run the API + client to perform CA actions
#./ci/run_api_and_client.py

# Check files created by the tests
#./ci/check_expected_files.sh
