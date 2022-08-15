// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES.
 */

#include <config.h>
#include <crypto/crypto.h>
#include <drivers/tegra/tegra_fuse.h>
#include <drivers/tegra/tegra_se_aes.h>
#include <drivers/tegra/tegra_se_kdf.h>
#include <drivers/tegra/tegra_se_keyslot.h>
#include <drivers/tegra/tegra_se_rng.h>
#include <initcall.h>
#include <pta_jetson_user_key.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/pseudo_ta.h>
#include <kernel/tee_common_otp.h>
#include <libfdt.h>
#include <stdio.h>
#include <string.h>
#include <trace.h>
#include <tee/tee_fs.h>

#include <mm/core_memprot.h>

#define JETSON_USER_KEY_PTA_NAME	"jetson_user_key_pta.ta"

static vaddr_t ekb_base_addr;

/*
 * Random fixed vector for EKB.
 *
 * Note: This vector MUST match the 'fv' vector used for EKB binary
 * generation process.
 * ba d6 6e b4 48 49 83 68 4b 99 2f e5 4a 64 8b b8
 */
static uint8_t fv_for_ekb[] = {
	0xba, 0xd6, 0x6e, 0xb4, 0x48, 0x49, 0x83, 0x68,
	0x4b, 0x99, 0x2f, 0xe5, 0x4a, 0x64, 0x8b, 0xb8,
};

/*
 * Random fixed vector used to derive SSK_DK (Derived Key).
 *
 * e4 20 f5 8d 1d ea b5 24 c2 70 d8 d2 3e ca 45 e8
 */
static uint8_t fv_for_ssk_dk[] = {
	0xe4, 0x20, 0xf5, 0x8d, 0x1d, 0xea, 0xb5, 0x24,
	0xc2, 0x70, 0xd8, 0xd2, 0x3e, 0xca, 0x45, 0xe8,
};

/*
 * Root keys derived from SE keyslots.
 */
static uint8_t ekb_rk[TEGRA_SE_KEY_128_SIZE] = { 0 };
static uint8_t ssk_rk[TEGRA_SE_KEY_128_SIZE] = { 0 };
#if defined(PLATFORM_FLAVOR_t194)
static uint8_t demo_256_rk[TEGRA_SE_KEY_256_SIZE] = { 0 };
#endif

/*
 * Derived keys from NIST-SP 800-108.
 */
static uint8_t ekb_ek[TEGRA_SE_KEY_128_SIZE] = { 0 };
static uint8_t ekb_ak[TEGRA_SE_KEY_128_SIZE] = { 0 };

#define TOTAL_USER_KEY_SIZE (EKB_USER_KEYS_NUM * TEGRA_SE_KEY_128_SIZE)

typedef struct user_sym_key {
	uint8_t kernel_encryption_key[TEGRA_SE_KEY_128_SIZE];
	uint8_t disk_encryption_key[TEGRA_SE_KEY_128_SIZE];
} user_sym_keys_t;
static user_sym_keys_t user_sym_keys;

struct ekb_content {
	uint8_t ekb_cmac[TEGRA_SE_AES_BLOCK_SIZE];
	uint8_t random_iv[TEGRA_SE_AES_IV_SIZE];
	uint8_t ekb_ciphertext[TOTAL_USER_KEY_SIZE];
};

static uint8_t rollbackkeyiv[TEGRA_SE_AES_IV_SIZE] = {
	'n', 'v', '-', 's', 't', 'o', 'r', 'a',
	'g', 'e', '-', 'd', 'u', 'm', 'm', 'y'
};

static uint8_t rollbackkeysrc[TEGRA_SE_AES_BLOCK_SIZE * 2] = {
	0x81, 0x2A, 0x01, 0x43, 0x6B, 0x7C, 0x19, 0xAA,
	0xFF, 0x22, 0x38, 0x82, 0x0A, 0x67, 0x74, 0x08,
	0x30, 0x06, 0xCA, 0x11, 0x41, 0x49, 0x80, 0xED,
	0xE7, 0xBB, 0x61, 0x01, 0x2F, 0x56, 0x9D, 0xD3
};

static uint8_t rollbackkey[TEGRA_SE_AES_BLOCK_SIZE * 2] = { 0 };

/*
 * HW unique key for tee_otp_get_hw_unique_key
 */
static struct tee_hw_unique_key *hw_unique_key = NULL;

/*
 * RPMB key readiness
 */
static bool jetson_rpmb_key_is_ready = false;

/*
 * Jetson service flag:
 *    LUKS_SRV_FLAG: Turn on/off for CA to query passphrase
 *    PTA_SRV_FLAG: Indicate the TA is available or not
 */
static uint32_t jetson_service_flag = LUKS_SRV_FLAG |
				      PTA_SRV_FLAG;

/*
 * A software-based NIST-SP 800-108 KDF.
 *  derives keys from a key in a key buffer.
 *
 * *key		[in] input key for derivation.
 * key_len	[in] length in bytes of the input key.
 * *context	[in] a pointer to a NIST-SP 800-108 context string.
 * *label	[in] a pointer to a NIST-SP 800-108 label string.
 * dk_len	[in] length of the derived key in bytes;
 *		     may be 16 (128 bits) or any multiple of 16.
 * *out_dk 	[out] a pointer to the derived key. The function stores
 *		      its result in this location.
 */
static TEE_Result nist_sp_800_108_cmac_kdf(uint8_t *key,
					   uint32_t key_len,
					   char const *context,
					   char const *label,
					   uint32_t dk_len,
					   uint8_t *out_dk)
{
	uint8_t counter[] = { 1 }, zero_byte[] = { 0 };
	uint32_t L[] = { TEE_U32_TO_BIG_ENDIAN(dk_len * 8) };
	uint8_t *message = NULL, *mptr;
	uint32_t msg_len, i, n;
	void *cmac_ctx = NULL;
	TEE_Result rc = TEE_SUCCESS;

	if ((key_len != TEGRA_SE_KEY_128_SIZE) &&
	    (key_len != TEGRA_SE_KEY_256_SIZE))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((dk_len % TEE_AES_BLOCK_SIZE) != 0)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!key || !context || !label || !out_dk)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 *  Regarding to NIST-SP 800-108
	 *  message = counter || label || 0 || context || L
	 *
	 *  A || B = The concatenation of binary strings A and B.
	 */
	msg_len = strlen(context) + strlen(label) + 2 + sizeof(L);
	message = calloc(1, msg_len);
	if (message == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	/* Concatenate the messages */
	mptr = message;
	memcpy(mptr, counter, sizeof(counter));
	mptr += sizeof(counter);
	memcpy(mptr, label, strlen(label));
	mptr += strlen(label);
	memcpy(mptr, zero_byte, sizeof(zero_byte));
	mptr += sizeof(zero_byte);
	memcpy(mptr, context, strlen(context));
	mptr += strlen(context);
	memcpy(mptr, L, sizeof(L));

	/* AES-CMAC */
	rc = crypto_mac_alloc_ctx(&cmac_ctx, TEE_ALG_AES_CMAC);
	if (rc)
		goto kdf_error;

	/* n: iterations of the PRF count */
	n = dk_len / TEE_AES_BLOCK_SIZE;

	for (i = 0; i < n; i++) {
		/* Update the counter */
		message[0] = i + 1;

		crypto_mac_init(cmac_ctx, key, key_len);
		crypto_mac_update(cmac_ctx, message, msg_len);
		crypto_mac_final(cmac_ctx, (out_dk + (i * TEE_AES_BLOCK_SIZE)),
				 TEE_AES_BLOCK_SIZE);
	}

	crypto_mac_free_ctx(cmac_ctx);

kdf_error:
	free(message);
	return rc;
}

static TEE_Result ekb_extraction_process(vaddr_t ekb_addr)
{
	TEE_Result rc = TEE_SUCCESS;
	struct ekb_content *ekb = (struct ekb_content*)ekb_addr;
	void *crypt_ctx = NULL;
	uint8_t ekb_cmac_verify[TEGRA_SE_AES_BLOCK_SIZE];

	/* Derive EKB_EK */
	rc = nist_sp_800_108_cmac_kdf(ekb_rk, TEGRA_SE_KEY_128_SIZE,
				      "ekb", "encryption",
				      TEGRA_SE_KEY_128_SIZE, ekb_ek);
	if (rc)
		return rc;

	/* Derive EKB_AK */
	rc = nist_sp_800_108_cmac_kdf(ekb_rk, TEGRA_SE_KEY_128_SIZE,
				      "ekb", "authentication",
				      TEGRA_SE_KEY_128_SIZE, ekb_ak);
	if (rc)
		return rc;

	/* Calculate the EKB CMAC */
	rc = crypto_mac_alloc_ctx(&crypt_ctx, TEE_ALG_AES_CMAC);
	if (rc)
		return rc;

	crypto_mac_init(crypt_ctx, ekb_ak, sizeof(ekb_ak));
	crypto_mac_update(crypt_ctx, ekb->random_iv, sizeof(ekb->random_iv) +
			  TEGRA_SE_KEY_128_SIZE * EKB_USER_KEYS_NUM);
	crypto_mac_final(crypt_ctx, ekb_cmac_verify, TEGRA_SE_AES_BLOCK_SIZE);
	crypto_mac_free_ctx(crypt_ctx);

	/* Verify the CMAC */
	if (memcmp(ekb->ekb_cmac, ekb_cmac_verify, TEGRA_SE_AES_BLOCK_SIZE)) {
		rc = TEE_ERROR_CIPHERTEXT_INVALID;
		return rc;
	}

	/* Decrypt the EKB ciphertext */
	rc = crypto_cipher_alloc_ctx(&crypt_ctx, TEE_ALG_AES_CBC_NOPAD);
	if (rc)
		return rc;

	crypto_cipher_init(crypt_ctx, TEE_MODE_DECRYPT,
			   ekb_ek, TEGRA_SE_KEY_128_SIZE,
			   NULL, 0,
			   ekb->random_iv, TEGRA_SE_AES_BLOCK_SIZE);
	crypto_cipher_update(crypt_ctx, TEE_MODE_DECRYPT, false,
			     ekb->ekb_ciphertext,
			     TEGRA_SE_KEY_128_SIZE * EKB_USER_KEYS_NUM,
			     (uint8_t*)&user_sym_keys);
	crypto_cipher_final(crypt_ctx);
	crypto_cipher_free_ctx(crypt_ctx);

	return rc;
}

static TEE_Result hwkey_derivation_process(void)
{
	TEE_Result rc = TEE_SUCCESS, err;
#if defined(PLATFORM_FLAVOR_t194)
	se_aes_keyslot_t fuse_key_for_ekb = SE_AES_KEYSLOT_KEK2_128B;
	se_aes_keyslot_t fuse_key_for_ssk = SE_AES_KEYSLOT_SSK;
	se_aes_keyslot_t fuse_key_for_rpmb = SE_AES_KEYSLOT_KEK1G_128B;
#endif
#if defined(PLATFORM_FLAVOR_t234)
	se_aes_keyslot_t fuse_key_for_ekb = SE_AES_KEYSLOT_OEM_K2;
	se_aes_keyslot_t fuse_key_for_ssk = SE_AES_KEYSLOT_OEM_K2;
	se_aes_keyslot_t fuse_key_for_rpmb = SE_AES_KEYSLOT_OEM_K1;
#endif

	/*
	 * Derive root keys by performing AES-ECB encryption with the fixed
	 * vector (fv) and keys in SE keyslots.
	 */
	rc = tegra_se_aes_ecb_kdf(ekb_rk, sizeof(ekb_rk),
				  fv_for_ekb, sizeof(fv_for_ekb),
				  fuse_key_for_ekb);
	if (rc != TEE_SUCCESS) {
		EMSG("%s: Failed to derive EKB root key (%x)", __func__, rc);
		goto key_derivation_fail;
	}

	rc = tegra_se_aes_ecb_kdf(ssk_rk, sizeof(ssk_rk),
				  fv_for_ssk_dk, sizeof(fv_for_ssk_dk),
				  fuse_key_for_ssk);
	if (rc != TEE_SUCCESS) {
		EMSG("%s: Failed to derive SSK root key (%x)", __func__, rc);
		goto key_derivation_fail;
	}

	rc = tegra_se_aes_encrypt_cbc(rollbackkeysrc, sizeof(rollbackkeysrc),
			rollbackkey, fuse_key_for_rpmb, rollbackkeyiv);
	if (rc != TEE_SUCCESS) {
		EMSG("%s: Failed to derive rollback key (%x)", __func__, rc);
		goto key_derivation_fail;
	} else {
		jetson_rpmb_key_is_ready = true;
	}

#if defined(PLATFORM_FLAVOR_t194)
	/*
	 * Derive 256-bit root key from KEK256 SE keyslot.
	 *
	 * To support this, you need to modify the BR BCT file
	 * e.g. "tegra194-br-bct-sdmmc.cfg" (or "tegra194-br-bct-qspi.cfg").
	 * Add "BctKEKKeySelect = 1" into the BR BCT file.
	 * The BootRom will check the BCT to load KEK0 and KEK1 as a single
	 * 256-bit fuse into KEK256 SE keyslot.
	 */
	rc = tegra_se_nist_sp_800_108_cmac_kdf(SE_AES_KEYSLOT_KEK256,
					       TEGRA_SE_KEY_256_SIZE,
					       "Derived 256-bit root key",
					       "256-bit key",
					       TEGRA_SE_KEY_256_SIZE,
					       demo_256_rk);
	if (rc != TEE_SUCCESS)
		EMSG("%s: Failed to derive 256-bit root key (%x).", __func__,
		     rc);
#endif

key_derivation_fail:
	/* Clear keys from SE keyslots */
	err = tegra_se_clear_aes_keyslots();
	if (err != TEE_SUCCESS)
		EMSG("%s: Failed to clear SE keyslots (%x).", __func__, err);
	if (rc == TEE_SUCCESS)
		rc = err;

	return rc;
}

/* Override the weak tee_otp_get_hw_unique_key */
TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	bool gen_unique_key_fail = false;

	if (hw_unique_key == NULL) {
		fuse_ecid_t *ecid;
		char ecid_str[36];
		TEE_Result rc;

		hw_unique_key = calloc(1, sizeof(struct tee_hw_unique_key));
		ecid = tegra_fuse_get_ecid();

		if ((hw_unique_key != NULL) && (ecid != NULL)) {
			snprintf(ecid_str, sizeof(ecid_str), "%08x%08x%08x%08x",
				 ecid->ecid[3], ecid->ecid[2], ecid->ecid[1],
				 ecid->ecid[0]);
			rc = nist_sp_800_108_cmac_kdf(ekb_rk,
						      TEGRA_SE_KEY_128_SIZE,
						      ecid_str,
						      "tee-hw-unique-key",
						      HW_UNIQUE_KEY_LENGTH,
						      hw_unique_key->data);
			if (rc)
				gen_unique_key_fail = true;
		} else {
			gen_unique_key_fail = true;
		}
	}

	if (gen_unique_key_fail) {
		memset(&hwkey->data[0], 0, sizeof(hwkey->data));
		if (hw_unique_key != NULL) {
			free(hw_unique_key);
			hw_unique_key = NULL;
		}
	} else {
		memcpy(hwkey->data, hw_unique_key->data, HW_UNIQUE_KEY_LENGTH);
	}

	return TEE_SUCCESS;
}

static TEE_Result jetson_pta_get_ekb_key(uint32_t ptypes,
					 TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	TEE_Result rc = TEE_SUCCESS;

	if (exp_pt != ptypes)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (params[0].value.a) {
	case EKB_USER_KEY_KERNEL_ENCRYPTION:
		if (params[1].memref.size == TEGRA_SE_KEY_128_SIZE)
			memcpy(params[1].memref.buffer,
			       user_sym_keys.kernel_encryption_key,
			       TEGRA_SE_KEY_128_SIZE);
		else
			rc = TEE_ERROR_NOT_SUPPORTED;
		break;
	case EKB_USER_KEY_DISK_ENCRYPTION:
		if (params[1].memref.size == TEGRA_SE_KEY_128_SIZE)
			memcpy(params[1].memref.buffer,
			       user_sym_keys.disk_encryption_key,
			       TEGRA_SE_KEY_128_SIZE);
		else
			rc = TEE_ERROR_NOT_SUPPORTED;
		break;
	default:
		rc = TEE_ERROR_NOT_SUPPORTED;
		break;
	}

	return rc;
}

/* Override the weak tee_otp_get_rpmb_key */
TEE_Result tee_otp_get_rpmb_key(uint8_t *key, size_t len)
{
	if (len != TEGRA_SE_AES_BLOCK_SIZE * 2) {
		EMSG("Invalid RPMB key length");
			return TEE_ERROR_BAD_PARAMETERS;
	}

	if (jetson_rpmb_key_is_ready) {
		memcpy(key, rollbackkey, len);
		return TEE_SUCCESS;
	} else {
		EMSG("Failed to get RPMB key");
		return TEE_ERROR_NO_DATA;
	}
}

#ifdef CFG_RPMB_FS
bool plat_rpmb_key_is_ready(void)
{
	return jetson_rpmb_key_is_ready;
}
#endif

static TEE_Result jetson_pta_get_random(uint32_t ptypes,
					TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	TEE_Result rc = TEE_SUCCESS;

	if (exp_pt != ptypes)
		return TEE_ERROR_BAD_PARAMETERS;

	rc = tegra_se_rng_get_random(params[0].memref.buffer,
				     params[0].memref.size);
	if (rc != TEE_SUCCESS) {
		memset(params[0].memref.buffer, 0, params[0].memref.size);
		params[0].memref.size = 0;
	}

	return rc;
}

static TEE_Result jetson_pta_gen_unique_key_by_ekb(uint32_t ptypes,
					TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_NONE);
	TEE_Result rc = TEE_SUCCESS;
	fuse_ecid_t *ecid;
	char ecid_str[36];
	uint8_t *key;

	if (exp_pt != ptypes)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (params[0].value.a) {
	case EKB_USER_KEY_DISK_ENCRYPTION:
		key = user_sym_keys.disk_encryption_key;
		break;
	case EKB_USER_KEY_KERNEL_ENCRYPTION:
		key = user_sym_keys.kernel_encryption_key;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	ecid = tegra_fuse_get_ecid();
	snprintf(ecid_str, sizeof(ecid_str), "%08x%08x%08x%08x",
		 ecid->ecid[3], ecid->ecid[2], ecid->ecid[1],
		 ecid->ecid[0]);

	rc = nist_sp_800_108_cmac_kdf(key, TEGRA_SE_KEY_128_SIZE,
				      ecid_str, params[1].memref.buffer,
				      params[2].memref.size,
				      params[2].memref.buffer);

	return rc;
}

static TEE_Result jetson_pta_gen_key(uint32_t ptypes,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_OUTPUT);
	TEE_Result rc = TEE_SUCCESS;

	if (exp_pt != ptypes)
		return TEE_ERROR_BAD_PARAMETERS;

	rc = nist_sp_800_108_cmac_kdf(params[0].memref.buffer,
				      params[0].memref.size,
				      params[1].memref.buffer,
				      params[2].memref.buffer,
				      params[3].memref.size,
				      params[3].memref.buffer);

	return rc;
}

static TEE_Result jetson_pta_get_flag(uint32_t ptypes,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_VALUE_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	TEE_Result rc = TEE_SUCCESS;

	if (exp_pt != ptypes)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (params[0].value.a) {
	case LUKS_SRV_FLAG:
		break;
	default:
		return TEE_ERROR_ACCESS_DENIED;
	}

	params[1].value.a = jetson_service_flag & params[0].value.a;

	return rc;
}

static TEE_Result jetson_pta_set_flag(uint32_t ptypes,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	TEE_Result rc = TEE_SUCCESS;

	if (exp_pt != ptypes)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (params[0].value.a) {
	case LUKS_SRV_FLAG:
		break;
	default:
		return TEE_ERROR_ACCESS_DENIED;
	}
	if (params[0].value.b)
		jetson_service_flag |= params[0].value.a;
	else
		jetson_service_flag &= ~params[0].value.a;

	return rc;
}

static TEE_Result invoke_command(void *psess __unused,
				 uint32_t cmd, uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	if (!(jetson_service_flag & PTA_SRV_FLAG))
		return TEE_ERROR_ACCESS_DENIED;

	switch(cmd) {
	case JETSON_USER_KEY_CMD_GET_EKB_KEY:
		return jetson_pta_get_ekb_key(ptypes, params);
	case JETSON_USER_KEY_CMD_GET_RANDOM:
		return jetson_pta_get_random(ptypes, params);
	case JETSON_USER_KEY_CMD_GEN_UNIQUE_KEY_BY_EKB:
		return jetson_pta_gen_unique_key_by_ekb(ptypes, params);
	case JETSON_USER_KEY_CMD_GEN_KEY:
		return jetson_pta_gen_key(ptypes, params);
	case JETSON_USER_KEY_CMD_GET_FLAG:
		return jetson_pta_get_flag(ptypes, params);
	case JETSON_USER_KEY_CMD_SET_FLAG:
		return jetson_pta_set_flag(ptypes, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result open_session(uint32_t param_types __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **sess_ctx __unused)
{
	struct ts_session *s = NULL;

	/* Check that we're called from a user TA */
	s = ts_get_calling_session();
	if (!s || !is_user_ta_ctx(s->ctx))
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

pseudo_ta_register(.uuid = JETSON_USER_KEY_UUID,
		   .name = JETSON_USER_KEY_PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .open_session_entry_point = open_session,
		   .invoke_command_entry_point = invoke_command);

static const char *const jetson_ekb_dt_match_table[] = {
	"jetson-ekb-blob",
};

static TEE_Result jetson_ekb_dt_init(void)
{
	void *fdt = NULL;
	int node = -1;
	uint32_t i = 0;
	paddr_t pbase;
	ssize_t sz;

	fdt = get_dt();
	if (!fdt) {
		EMSG("%s: DTB is not present.", __func__);
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	for (i = 0; i < ARRAY_SIZE(jetson_ekb_dt_match_table); i++) {
		node = fdt_node_offset_by_compatible(fdt, 0,
					jetson_ekb_dt_match_table[i]);
		if (node >= 0)
			break;
	}

	if (node < 0) {
		EMSG("%s: DT not found (%x).", __func__, node);
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	pbase = _fdt_reg_base_address(fdt, node);
	if (pbase == DT_INFO_INVALID_REG)
		return TEE_ERROR_GENERIC;

	sz = _fdt_reg_size(fdt, node);
	if (sz < 0)
		return TEE_ERROR_GENERIC;

	if (!core_mmu_add_mapping(MEM_AREA_RAM_SEC, pbase, sz)) {
		EMSG("Failed to map %zu bytes at PA 0x%"PRIxPA,
		     (size_t)sz, pbase);
		return TEE_ERROR_GENERIC;
	}

	ekb_base_addr = (vaddr_t)phys_to_virt(pbase, MEM_AREA_RAM_SEC, sz);
	if (!ekb_base_addr) {
		EMSG("Failed to get VA for PA 0x%"PRIxPA, pbase);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

static TEE_Result jetson_user_key_pta_init(void)
{
	TEE_Result rc = TEE_SUCCESS;

	if (!IS_ENABLED(CFG_DT)) {
		rc = TEE_ERROR_NOT_SUPPORTED;
		goto pta_init_fail;
	}

	rc = jetson_ekb_dt_init();
	if (rc)
		goto pta_init_fail;

	/* Derive keys from SE keyslots. */
	rc = hwkey_derivation_process();
	if(rc)
		goto pta_init_fail;

	/* EKB extraction */
	rc = ekb_extraction_process(ekb_base_addr);
	if (rc)
		goto pta_init_fail;

#if defined(PLATFORM_FLAVOR_t194)
	/* Set ekb key to SBK key slot to support for cboot crypto operation */
	tegra_se_write_aes_keyslot(user_sym_keys.kernel_encryption_key,
				   TEGRA_SE_KEY_128_SIZE,
				   TEGRA_SE_AES_QUAD_KEYS_128,
				   SE_AES_KEYSLOT_SBK);
#endif

pta_init_fail:
	if (rc) {
		jetson_service_flag &= !PTA_SRV_FLAG;
		EMSG("%s: Failed (%x).", __func__, rc);
	}

	return rc;
}

service_init_late(jetson_user_key_pta_init);
