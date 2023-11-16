// Copyright (c) 2022 Fraunhofer AISEC

#pragma once

/* Reduce RAM usage.*/
/* More info: https://tls.mbed.org/kb/how-to/reduce-mbedtls-memory-and-storage-footprint */
#define MBEDTLS_ECP_FIXED_POINT_OPTIM 0 /* To reduce peak memory usage */
#define MBEDTLS_AES_ROM_TABLES
#define MBEDTLS_SSL_MAX_CONTENT_LEN (1024 * 10) /* Reduce SSL frame buffer. */
#define MBEDTLS_MPI_WINDOW_SIZE 1
#define MBEDTLS_ECP_WINDOW_SIZE 2
#define MBEDTLS_MPI_MAX_SIZE 512 /* Maximum number of bytes for usable MPIs. */
#define MBEDTLS_ECP_MAX_BITS 384 /* Maximum bit size of groups */

#define MBEDTLS_HAVE_ASM

#define MBEDTLS_REMOVE_ARC4_CIPHERSUITES
#define MBEDTLS_REMOVE_3DES_CIPHERSUITES

#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_NIST_OPTIM

#define MBEDTLS_NO_PLATFORM_ENTROPY

#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_BIGNUM_C

#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_C
#define MBEDTLS_HMAC_DRBG_C

#define MBEDTLS_MD_C

#define MBEDTLS_OID_C

#define MBEDTLS_PEM_PARSE_C

#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_WRITE_C

#define MBEDTLS_SHA256_C

#if defined(MBEDTLS_USER_CONFIG_FILE)
#include MBEDTLS_USER_CONFIG_FILE
#endif

#include "mbedtls/check_config.h"
