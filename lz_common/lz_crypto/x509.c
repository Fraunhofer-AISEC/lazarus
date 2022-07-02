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

#ifdef MBEDTLS_CONFIG_FILE

#include MBEDTLS_CONFIG_FILE

#if defined(MBEDTLS_X509_USE_C) && defined(MBEDTLS_X509_CREATE_C)

#include <stdio.h>

#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/pk.h"

#include "lz_config.h"
#include "crypto_common.h"
#include "x509.h"

#define SERIAL_NUMBER_FIELD_LENGTH 14

size_t lz_x509_get_dn_length(const lz_x509_dn_info *info)
{
	return strlen(info->common_name) + strlen(info->org) + strlen(info->country) + 10;
}

int lz_x509_dn_to_string(const lz_x509_dn_info *info, char *buf, size_t buf_size)
{
	if (buf_size < x509_get_dn_length(info)) {
		dbgprint(DBG_INFO, "ERROR: Buffer too small for csr info.\n");
		return -1;
	}
	int n = snprintf(buf, buf_size, "CN=%s,O=%s,C=%s", info->common_name, info->org, info->country);
	if ((n >= (int)buf_size) || n < 0) {
		dbgprint(DBG_INFO, "ERROR: Could not successfully write to buffer.\n");
		return -1;
	}
	return n;
}

int lz_write_csr_to_pem(const lz_x509_csr_info *info, lz_ecc_keypair *keypair, unsigned char *buf,
						size_t buf_size)
{
	mbedtls_x509write_csr req;
	mbedtls_x509write_csr_init(&req);

	int re = 0;

	mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);
	mbedtls_x509write_csr_set_key(&req, keypair);

	int dn_buf_size = x509_get_dn_length(&info->subject) + SERIAL_NUMBER_FIELD_LENGTH +
					  sizeof(info->serial_number);
	char *dn_buf = malloc(dn_buf_size);
	CHECK(x509_dn_to_string(&info->subject, dn_buf, dn_buf_size), "Error copying information");

	memccpy(dn_buf + re + 1, info->serial_number, 1, sizeof(info->serial_number));
	re += sizeof(info->serial_number);
	dn_buf[re] = 0;

	CHECK(mbedtls_x509write_csr_set_subject_name(&req, dn_buf),
		  "Error setting subject name for CSR");

	// Writing to the buffer
	CHECK(mbedtls_x509write_csr_pem(&req, buf, buf_size, lz_rand, NULL),
		  "Error while writing CSR as DER");

clean:
	free(dn_buf);
	mbedtls_x509write_csr_free(&req);
	return re;
}

int lz_write_cert_to_pem(const lz_x509_cert_info *info, lz_ecc_keypair *subject_keys,
						 lz_ecc_keypair *issuer_keys, unsigned char *buf, size_t buf_size)
{
	mbedtls_x509write_cert cert;
	mbedtls_x509write_crt_init(&cert);
	mbedtls_mpi serial_number;
	mbedtls_mpi_init(&serial_number);
	char *issuer_buf = 0;
	char *subject_buf = 0;
	int re = 0;

	mbedtls_x509write_crt_set_subject_key(&cert, subject_keys);
	mbedtls_x509write_crt_set_issuer_key(&cert, issuer_keys);

	size_t issuer_buf_size = x509_get_dn_length(&info->issuer);
	issuer_buf = malloc(issuer_buf_size);
	x509_dn_to_string(&info->issuer, issuer_buf, issuer_buf_size);
	CHECK(mbedtls_x509write_crt_set_issuer_name(&cert, issuer_buf),
		  "Failed setting the issuer name in cert");

	size_t subject_buf_size = x509_get_dn_length(&info->subject);
	subject_buf = malloc(subject_buf_size);
	x509_dn_to_string(&info->subject, subject_buf, subject_buf_size);
	CHECK(mbedtls_x509write_crt_set_subject_name(&cert, subject_buf),
		  "Failed setting the subject name in cert");

	CHECK(mbedtls_x509write_crt_set_validity(&cert, "20170101000000", "20370101000000"),
		  "Failed setting the validity in cert");

	CHECK(mbedtls_mpi_read_binary(&serial_number, (unsigned char *)info->serial_number,
								  sizeof(info->serial_number)),
		  "Error converting serial number to MPI");
	CHECK(mbedtls_x509write_crt_set_serial(&cert, &serial_number),
		  "Failed setting the serial_number in cert");
	CHECK(mbedtls_x509write_crt_set_key_usage(&cert, MBEDTLS_X509_KU_KEY_CERT_SIGN),
		  "Failed setting the key usage in cert");
	mbedtls_x509write_crt_set_version(&cert, MBEDTLS_X509_CRT_VERSION_3);
	mbedtls_x509write_crt_set_md_alg(&cert, MBEDTLS_MD_SHA256);

	CHECK(mbedtls_x509write_crt_set_authority_key_identifier(&cert),
		  "Failed setting the authority key identifier");

	// TODO: Add extKeyUsage to id-kp-clientAuth
	// CHECK(mbedtls_x509write_crt_set_extension(&cert,), "Failed setting the key usage in cert");

	CHECK(mbedtls_x509write_crt_pem(&cert, buf, buf_size, lz_rand, 0),
		  "Failed writing the cert as pem");

	// Signed von der device ID

clean:
	free(issuer_buf);
	free(subject_buf);
	mbedtls_mpi_free(&serial_number);
	mbedtls_x509write_crt_free(&cert);

	return re;
}

#ifdef MBEDTLS_HKDF_C

int lz_set_serial_number_csr(lz_x509_csr_info *info, const unsigned char *salt, size_t salt_len)
{
	return mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0, salt, salt_len, NULL,
						0, (unsigned char *)info->serial_number, sizeof(info->serial_number));
}

int lz_set_serial_number_cert(lz_x509_cert_info *info, const unsigned char *salt, size_t salt_len)
{
	return mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0, salt, salt_len, NULL,
						0, (unsigned char *)info->serial_number, sizeof(info->serial_number));
}

#endif

#endif

#endif /* MBEDTLS_CONFIG_FILE */
