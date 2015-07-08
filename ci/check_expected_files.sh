#!/bin/bash

WORKSPACE="${PWD}/workspace"
EXPECTED_FILES="${PWD}/ci/expected_files.list"

function info {
    echo "[+] ${@}"
}

function warning {
    echo "[W] ${@}"
}

function error {
    echo "[E] ${@}"
    exit 1
}

if [ ! -f "./ci/run_tests.sh" ]; then
    error "Invalid PWD"
fi

if [ ! -d "${WORKSPACE}" ]; then
    error "${WORKSPACE} does not exist"
fi

if [ ! -f "${EXPECTED_FILES}" ]; then
    error "${EXPECTED_FILES} does not exist"
fi

info "Checking expected files"
for FILE in $(cat ${EXPECTED_FILES}); do
    FNAME="${WORKSPACE}/${FILE}"
    if [ ! -f "${FNAME}" ]; then
        warning "${FILE} not found"
    fi
done
