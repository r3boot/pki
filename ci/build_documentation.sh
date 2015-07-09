#!/bin/bash

DEST='/srv/software/documentation/pki'

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

pushd doc >/dev/null 2>&1

info "Generating documentation"
make html

info "Installing documentation"
rsync -avl --delete ./build/html/* ${DEST}/

popd >/dev/null 2>&1
