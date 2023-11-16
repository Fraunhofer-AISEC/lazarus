#!/bin/bash

set -e

trap '[ $? -eq 0 ] && exit 0; printf "[\033[31;1mFAILED\033[0m] %s\n" "$0"' EXIT

dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"

certdir

mkdir -p ${dir}/lz_hub/certificates
cd ${dir}/lz_hub/certificates

# Generate certs
openssl req -x509 -nodes -days 3650 -newkey ec:<(openssl ecparam -name prime256v1) \
    -keyout code_auth_sk.pem -out code_auth_cert.pem

openssl req -x509 -nodes -days 3650 -newkey ec:<(openssl ecparam -name prime256v1) \
    -keyout hub_sk.pem -out hub_cert.pem

# Write certs to database
python3 ${dir}/lz_certs_provision.py