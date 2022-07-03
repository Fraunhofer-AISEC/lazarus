/*
 * Copyright(c) 2021 Fraunhofer AISEC
 * Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#ifdef MBEDTLS_CONFIG_FILE

#include MBEDTLS_CONFIG_FILE

#if defined(MBEDTLS_X509_USE_C) && defined(MBEDTLS_X509_CREATE_C)

#include <stdint.h>

#include "ecdsa.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/hkdf.h"

// Length of the serial number in X509 certificates/CSRs
#define SERIAL_NUMBER_LENGTH 8

typedef struct {
	char *common_name;
	char *org;
	char *country;
} x509_dn_info;

typedef struct {
	x509_dn_info subject;

	char serial_number[SERIAL_NUMBER_LENGTH];
} x509_csr_info;

typedef struct {
	x509_dn_info issuer;
	x509_dn_info subject;

	char serial_number[SERIAL_NUMBER_LENGTH];
} x509_cert_info;

// Writes and signs an x509_csr_info struct to a buffer in PEM format.
// Adds the given public key to the CSR and signs the CSR with the given
// private key
int x509_write_csr_to_pem(const x509_csr_info *info, ecc_keypair_t *keypair, unsigned char *buf,
						size_t buf_size);

// Writes and signs an x509_cert_info struct to a buffer in PEM format.
int x509_write_cert_to_pem(const x509_cert_info *info, ecc_keypair_t *subject_keys,
						 ecc_keypair_t *issuer_keys, unsigned char *buf, size_t buf_size);

#ifdef MBEDTLS_HKDF_C

// Sets the serial number of a csr using a given salt
int x509_set_serial_number_csr(x509_csr_info *info, const unsigned char *salt, size_t salt_len);

// Sets the serial number of a cert using a given salt
int x509_set_serial_number_cert(x509_cert_info *info, const unsigned char *salt, size_t salt_len);

#endif

#endif

#endif /* MBEDTLS_CONFIG_FILE */
