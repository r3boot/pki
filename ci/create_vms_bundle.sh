#!/bin/bash

DEST='/srv/software/vms/pki'

function info {
    echo "[+] ${@}"
}

function error {
    echo "[E] ${@}"
    exit 1
}

if [ ! -f "./ci/build_documentation.sh" ]; then
    error "Invalid PWD"
fi

info "Generating VMS bundle"
./scripts/vms/vmsbundle -d \
    -f ./config/pki.yml -l ./config/logging.yml \
    -w /cluster/temp -o ${DEST}/pki-vms-0.2.zip
