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

#ifndef LZ_COMMON_H_
#define LZ_COMMON_H_

#include <time.h>
#include "lz_common/lz_error.h"
#include "lzport_memory/lzport_memory.h"

#include "lz_crypto/lz_crypto_common.h"

/*******************************************
 * Definitions
 *******************************************/

#define FLASH_PAGE_SIZE	512

#define LEN_NONCE (32)
#define LEN_UUID_V4_BIN (16)
#define LEN_BINARY_NAME (32)

// Index of the certificates in the certificate bags of the Lazarus data store and Image data store
#define INDEX_LZ_CERTSTORE_HUB (0)
#define INDEX_LZ_CERTSTORE_DEVICEID (1)
#define INDEX_IMG_CERTSTORE_ALIASID (0)
#define INDEX_IMG_CERTSTORE_DEVICEID (1)
#define INDEX_IMG_CERTSTORE_HUB (2)

/** Default AWDT timeout in case of missing ticket */
#define DEFAULT_WDT_TIMOUT_s (60 * 60)

/** Magic value for all Lazarus structures */
#define LZ_MAGIC (0x41495345)

/** The certificate chain consists of the hub cert, DeviceID cert and AliasID cert */
#define NUM_CERTS (3)

/**
 * Command that can be sent as payload of a hdr_type_t CMD packet as the payload to
 * acknowledge the reception of a packet
 */
#define TCP_CMD_ACK 0x3
/**
 * Command that can be sent as payload of a hdr_type_t CMD unauthenticated packet as the payload
 * to dis-acknowledge the reception and processing of a packet
 */
#define TCP_CMD_NAK 0x2

/**
 * Macro to generate the enum and a string list for debugging of all the generic header types
 * (authenticated and unauthenticated) that are possible
 */
#define FOREACH_GEN_HDR_TYPE(GEN_HDR_TYPE)                                                         \
	GEN_HDR_TYPE(LZ_CORE_UPDATE)                                                                   \
	GEN_HDR_TYPE(LZ_UDOWNLOADER_UPDATE)                                                            \
	GEN_HDR_TYPE(LZ_CPATCHER_UPDATE)                                                               \
	GEN_HDR_TYPE(APP_UPDATE)                                                                       \
	GEN_HDR_TYPE(CERTS_UPDATE)                                                                     \
	GEN_HDR_TYPE(CONFIG_UPDATE)                                                                    \
	GEN_HDR_TYPE(ALIAS_ID)                                                                         \
	GEN_HDR_TYPE(DEVICE_ID_REASSOC_REQ)                                                            \
	GEN_HDR_TYPE(CERTS_UPDATE_REQ)                                                                 \
	GEN_HDR_TYPE(BOOT_TICKET)                                                                      \
	GEN_HDR_TYPE(DEFERRAL_TICKET)                                                                  \
	GEN_HDR_TYPE(CMD)                                                                              \
	GEN_HDR_TYPE(SENSOR_DATA)

#define GENERATE_ENUM(ENUM) ENUM,
#define GENERATE_STRING(STRING) #STRING,

/**
 * Automatically generated Enum for the generic header types. See macro above for the actual types
 */
typedef enum { FOREACH_GEN_HDR_TYPE(GENERATE_ENUM) } hdr_type_t;

/**
 * Generated string list for the generic header types. See macro above for the actual types
 */
__attribute__((unused)) static const char *HDR_TYPE_STRING[] = { FOREACH_GEN_HDR_TYPE(
	GENERATE_STRING) };

/**
 * DICEpp reads the requested boot mode, which is usually set by the
 * App, update downloader or core patcher and hands over the value to Lazarus Core. Depending  on
 * available tickets and content of staging area, Lazarus Core might decide otherwise
 */
typedef enum { APP, LZ_UDOWNLOADER, LZ_CPATCHER } boot_mode_t;

/**
 * Structure that represents the staging area in flash. The last word of the staging area is used
 * to indicate a boot mode request from an upper layer to Dice++ and Lazarus Core
 */
typedef struct {
	uint8_t content[LZ_STAGING_AREA_SIZE - sizeof(uint32_t)];
	uint32_t boot_mode_flag;
} lz_staging_area_t;

/*******************************************
 * Lazarus Headers
 *******************************************/

/**
 * Generic header for unauthenticated communication with the backend. The header is prepended
 * to packets that do not require authentication, such as some uncritical ACK's or where
 * authentication is neither possible nor necessary, such as the sending of the AliasID
 * certificate (as long as the backend does not have the AliasID certificate, it cannot
 * verify lazarus signatures anyway)
 */
typedef struct {
	hdr_type_t type;			   // Type of the packet
	uint32_t payload_size;		   // Size of the payload
	uint8_t uuid[LEN_UUID_V4_BIN]; // Identification of the device
} hdr_t;

/**
 * Generic header for all lazarus authenticated network packets and also to staging elements.
 * This header is prepended to all ticket requests, firmware or lazarus updates and certificate
 * updates. For tickets, the header already contains all essential information such as
 * nonce and signature. The payload is only a dummy in case of boot tickets or the AWDT reset
 * time in case of deferral tickets.
 */
typedef struct {
	struct {
		hdr_type_t type;					  // Type of the packet
		uint32_t payload_size;				  // Size of the payload
		uint8_t uuid[LEN_UUID_V4_BIN];		  // Identification of the device
		uint32_t magic;						  // Indicates that a sane header is written
		uint8_t nonce[LEN_NONCE];			  // Nonce used for signing the header
		uint8_t digest[SHA256_DIGEST_LENGTH]; // Hash of the payload
	} content;
	// Signature over all elements of the header
	lz_ecc_signature signature;
} lz_auth_hdr_t;

/*******************************************
 * Image Header
 *******************************************/

/**
 * Image header for all lazarus images
 */
typedef union {
	struct {
		struct {
			uint32_t magic;
			uint32_t hdr_size;
			char name[LEN_BINARY_NAME];
			uint32_t version;
			uint32_t size;
			time_t issue_time;
			uint8_t digest[SHA256_DIGEST_LENGTH];
		} content;
		lz_ecc_signature signature;
	} hdr;
	uint8_t u8[0x800];
} lz_img_hdr_t;

/*******************************************
 * Image Certificate Store
 *******************************************/

// Structure to locate images in the certificate bags
typedef struct {
	uint16_t start;
	uint16_t size;
} lz_img_cert_index_t;

// Structure that holds the trust anchor's public keys and information to locate the
// certificates in the certificate bag
typedef struct {
	uint32_t magic; // Indicates the next layer that the passed structure is in good state
	lz_ecc_pub_key_pem dev_pub_key;
	lz_ecc_pub_key_pem code_auth_pub_key;
	lz_ecc_pub_key_pem management_pub_key;

	lz_img_cert_index_t certTable[NUM_CERTS]; // Root, DeviceID and AliasID cert
	uint32_t cursor; // Cursor points to the end of the last element in the certBag
} lz_img_cert_store_info_t;

/**
 * Image certificate store that holds all public keys and certificates. The structure has a
 * fixed location in RAM and a fixed size of 4K. This structure is used to pass all certificate's
 * to the upper layers
 */
typedef struct {
	lz_img_cert_store_info_t info;
	// We place the different PEM-encoded certificate chain into the certBag.
	// Attention: When adding new certificates, make sure not to exceed the bounds.
	// Remaining size can e.g., be determined when debugging: sizeof certBag minus cursor position.
	uint8_t certBag[0x1000 - sizeof(lz_img_cert_store_info_t)];
} lz_img_cert_store_t;

/*******************************************
 * Lazarus Data Store
 *******************************************/

typedef struct {
	uint32_t magic;
	lz_ecc_pub_key_pem dev_pub_key;
	lz_ecc_pub_key_pem code_auth_pub_key;
	lz_ecc_pub_key_pem management_pub_key;

	lz_img_cert_index_t certTable[2]; // Hub and DeviceID cert
	uint32_t cursor;				  // Cursor points to the end of the last element in the certBag
} trust_anchors_info_t;

typedef struct {
	trust_anchors_info_t info;
	// certificate store for all PEM encoded certs
	uint8_t certBag[0x1000 - sizeof(trust_anchors_info_t)];
} trust_anchors_t;

/* CONFIG_DATA */
typedef struct {
	uint32_t magic;						 // Magic value indicating sane state of the struct
	uint8_t static_symm[SYM_KEY_LENGTH]; // Afterwards, static_symm is zero'd
	uint8_t dev_uuid[LEN_UUID_V4_BIN];
} static_symm_info_t;

// Network configuration
// TODO define reasonable sizes for the arrays
typedef struct {
	uint32_t magic;		 // Indicates whether config has been set
	char wifi_ssid[128]; // AP SSID
	char wifi_pwd[64];	 // Wifi PWD
	char wifi_auth_method[32];
	char server_ip_addr[48];
	uint32_t server_port;
} lz_nw_data_info_t;

// Image Meta Data structure
typedef struct {
	uint32_t magic;			// Indicates that the image is present on the device
	uint32_t lastVersion;	// Version of the last build
	time_t last_issue_time; // Time image was signed
} lz_img_meta_t;

typedef struct {
	lz_img_meta_t rc_meta;
	lz_img_meta_t um_meta;
	lz_img_meta_t ud_meta;
	lz_img_meta_t app_meta;
} lz_img_data_info_t;

typedef struct {
	lz_img_data_info_t img_info;
	static_symm_info_t static_symm_info;
	lz_nw_data_info_t nw_info;
	// Size of the config structure is currently 4k (TODO could be reduced)
	uint8_t pad[0x1000 - sizeof(static_symm_info_t) - sizeof(lz_nw_data_info_t) -
				sizeof(lz_img_data_info_t)];
} lz_config_data_t;

/**
 * Lazarus Data Store consists of trust anchors (4K) and configuration data (4K) and is placed
 * in a fixed location in flash memory
 */
typedef struct {
	trust_anchors_t trust_anchors; // 4k space for public keys and certificates
	lz_config_data_t config_data;  // 4k space for device config
} lz_data_store_t;

/*******************************************
 * Image Boot Parameters
 *******************************************/

typedef struct {
	uint32_t magic;
	lz_ecc_pub_key_pem alias_id_keypair_pub;
	lz_ecc_priv_key_pem alias_id_keypair_priv;
	uint8_t cur_nonce[LEN_NONCE];
	uint8_t next_nonce[LEN_NONCE];
	uint8_t dev_uuid[LEN_UUID_V4_BIN];
	bool dev_reassociation_necessary;
	bool firmware_update_necessary;
	uint8_t dev_auth[SHA256_DIGEST_LENGTH];
	lz_nw_data_info_t nw_data;
} lz_img_boot_params_info_t;

/**
 * 2K SRAM Image Boot Parameters for the upper layers
 */
typedef union {
	lz_img_boot_params_info_t info;
	uint8_t u8[0x800];
	uint32_t u32[0x200];
} lz_img_boot_params_t;

/*******************************************
 * Lazarus Core SRAM Boot Parameters
 *******************************************/

typedef struct {
	uint32_t magic;
	uint32_t initial_boot;
	boot_mode_t req_boot_mode;
	uint8_t cur_nonce[LEN_NONCE];
	uint8_t next_nonce[LEN_NONCE];
	uint8_t cdi_prime[SHA256_DIGEST_LENGTH];
	uint8_t dev_uuid[LEN_UUID_V4_BIN];
	uint8_t static_symm[SYM_KEY_LENGTH];
	uint8_t core_auth[SHA256_DIGEST_LENGTH];
} lz_core_boot_params_info;

/**
 * 2K Lazarus Core SRAM Boot Params
 */
typedef union {
	lz_core_boot_params_info info;
	uint8_t u8[0x800];
	uint32_t u32[0x200];
} lz_core_boot_params_t;

/*******************************************
 * Global Variables
 *******************************************/

extern volatile lz_img_boot_params_t lz_img_boot_params;
extern volatile lz_img_cert_store_t lz_img_cert_store;
extern volatile lz_staging_area_t lz_staging_area;

extern volatile lz_data_store_t lz_data_store;
extern volatile lz_img_hdr_t lz_core_hdr;
extern volatile lz_img_hdr_t lz_cpatcher_hdr;
extern volatile lz_img_hdr_t lz_udownloader_hdr;
extern volatile lz_img_hdr_t lz_app_hdr;

/*******************************************
 * Function prototypes
 *******************************************/

void lz_get_uuid(uint8_t uuid[LEN_UUID_V4_BIN]);
LZ_RESULT lz_set_boot_mode_request(boot_mode_t boot_mode_param);
LZ_RESULT lz_has_valid_boot_params(void);
LZ_RESULT lz_get_next_staging_hdr(lz_auth_hdr_t **hdr);
LZ_RESULT lz_get_staging_hdr(hdr_type_t hdr_type, lz_auth_hdr_t **return_hdr, uint8_t *nonce);
bool lz_dev_reassociation_necessary(void);
bool lz_firmware_update_necessary(void);
bool lz_is_mem_zero(const void *dataPtr, uint32_t dataSize);
bool lz_check_update_size(lz_auth_hdr_t *staging_elem_hdr);
void lz_error_handler(void);
LZ_RESULT
lz_flash_staging_element(uint8_t *buf, uint32_t buf_size, uint32_t total_size, uint32_t pending);
void lz_print_img_info(const char *img_name, volatile lz_img_hdr_t *img_hdr);

/**
 * Prevent compiler from optimizing out memset.
 * @param v Memory to be zeroed
 * @param n Size of the memory in bytes
 */
static inline void secure_zero_memory(void *v, size_t n)
{
	static void *(*const volatile memset_v)(void *, int, size_t) = &memset;
	memset_v(v, 0, n);
}

#endif /* LZ_COMMON_H_ */
