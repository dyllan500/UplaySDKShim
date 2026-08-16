#include "games/farcry5/cng_debug.h"
#include "core/config.h"
#include "core/logging.h"

#include <cstdio>
#include <cstdint>
#include <cstring>

namespace {
using ntstatus_t = LONG;
using bcrypt_handle_t = void*;
struct BCryptBuffer {
    ULONG cbBuffer;
    ULONG BufferType;
    void* pvBuffer;
};
struct BCryptBufferDesc {
    ULONG ulVersion;
    ULONG cBuffers;
    BCryptBuffer* pBuffers;
};
typedef ntstatus_t (WINAPI *bcrypt_open_algorithm_t)(bcrypt_handle_t*, LPCWSTR, LPCWSTR, ULONG);
typedef ntstatus_t (WINAPI *bcrypt_import_key_pair_t)(bcrypt_handle_t, bcrypt_handle_t, LPCWSTR,
                                                       bcrypt_handle_t*, unsigned char*, ULONG, ULONG);
typedef ntstatus_t (WINAPI *bcrypt_export_key_t)(bcrypt_handle_t, bcrypt_handle_t, LPCWSTR,
                                                  unsigned char*, ULONG, ULONG*, ULONG);
typedef ntstatus_t (WINAPI *bcrypt_create_hash_t)(bcrypt_handle_t, bcrypt_handle_t*, unsigned char*,
                                                   ULONG, unsigned char*, ULONG, ULONG);
typedef ntstatus_t (WINAPI *bcrypt_hash_data_t)(bcrypt_handle_t, unsigned char*, ULONG, ULONG);
typedef ntstatus_t (WINAPI *bcrypt_finish_hash_t)(bcrypt_handle_t, unsigned char*, ULONG, ULONG);
typedef ntstatus_t (WINAPI *bcrypt_secret_agreement_t)(bcrypt_handle_t, bcrypt_handle_t,
                                                        bcrypt_handle_t*, ULONG);
typedef ntstatus_t (WINAPI *bcrypt_derive_key_t)(bcrypt_handle_t, LPCWSTR, BCryptBufferDesc*,
                                                  unsigned char*, ULONG, ULONG*, ULONG);
typedef ntstatus_t (WINAPI *bcrypt_verify_signature_t)(bcrypt_handle_t, void*, unsigned char*, ULONG,
                                                        unsigned char*, ULONG, ULONG);
typedef ntstatus_t (WINAPI *bcrypt_crypt_t)(bcrypt_handle_t, unsigned char*, ULONG, void*,
                                             unsigned char*, ULONG, unsigned char*, ULONG, ULONG*, ULONG);

static bcrypt_open_algorithm_t g_bcrypt_open_algorithm = nullptr;
static bcrypt_import_key_pair_t g_bcrypt_import_key_pair = nullptr;
static bcrypt_export_key_t g_bcrypt_export_key = nullptr;
static bcrypt_create_hash_t g_bcrypt_create_hash = nullptr;
static bcrypt_hash_data_t g_bcrypt_hash_data = nullptr;
static bcrypt_finish_hash_t g_bcrypt_finish_hash = nullptr;
static bcrypt_secret_agreement_t g_bcrypt_secret_agreement = nullptr;
static bcrypt_derive_key_t g_bcrypt_derive_key = nullptr;
static bcrypt_verify_signature_t g_bcrypt_verify_signature = nullptr;
static bcrypt_crypt_t g_bcrypt_encrypt = nullptr;
static bcrypt_crypt_t g_bcrypt_decrypt = nullptr;

static void cng_wide_ascii(const wchar_t* source, char* dest, size_t cap) {
    if (!cap) return;
    if (!source) {
        dest[0] = '-';
        dest[1 < cap ? 1 : 0] = '\0';
        return;
    }
    size_t i = 0;
    for (; i + 1 < cap && i < 120 && source[i]; ++i) {
        wchar_t c = source[i];
        dest[i] = c >= 0x20 && c <= 0x7e ? (char)c : '?';
    }
    dest[i] = '\0';
}

static void cng_log_blob(const char* label, const void* data, ULONG size) {
    constexpr ULONG max_dump = 512;
    if (!data || !size) {
        shim_log("[cng] %s len=%lu", label, (unsigned long)size);
        return;
    }
    ULONG dump = size < max_dump ? size : max_dump;
    if (IsBadReadPtr(data, dump)) {
        shim_log("[cng] %s len=%lu unreadable", label, (unsigned long)size);
        return;
    }
    char prefix[96] = {};
    snprintf(prefix, sizeof(prefix), "[cng] %s len=%lu", label, (unsigned long)size);
    shim_log_bytes(prefix, data, (int)dump);
    if (dump != size) shim_log("[cng] %s truncated to %lu bytes", label, (unsigned long)dump);
}

static ntstatus_t WINAPI hook_BCryptOpenAlgorithmProvider(bcrypt_handle_t* algorithm,
                                                           LPCWSTR algorithm_id,
                                                           LPCWSTR implementation,
                                                           ULONG flags) {
    ntstatus_t status = g_bcrypt_open_algorithm
        ? g_bcrypt_open_algorithm(algorithm, algorithm_id, implementation, flags) : (ntstatus_t)0xC0000002L;
    char alg[128] = {}, impl[128] = {};
    cng_wide_ascii(algorithm_id, alg, sizeof(alg));
    cng_wide_ascii(implementation, impl, sizeof(impl));
    shim_log("[cng] BCryptOpenAlgorithmProvider alg=%s impl=%s flags=0x%lx status=0x%08lx handle=%p",
             alg, impl, (unsigned long)flags, (unsigned long)status, algorithm ? *algorithm : nullptr);
    return status;
}

static ntstatus_t WINAPI hook_BCryptImportKeyPair(bcrypt_handle_t algorithm, bcrypt_handle_t import_key,
                                                   LPCWSTR blob_type, bcrypt_handle_t* key,
                                                   unsigned char* input, ULONG input_size, ULONG flags) {
    ntstatus_t status = g_bcrypt_import_key_pair
        ? g_bcrypt_import_key_pair(algorithm, import_key, blob_type, key, input, input_size, flags)
        : (ntstatus_t)0xC0000002L;
    char type[128] = {};
    cng_wide_ascii(blob_type, type, sizeof(type));
    shim_log("[cng] BCryptImportKeyPair type=%s flags=0x%lx status=0x%08lx key=%p",
             type, (unsigned long)flags, (unsigned long)status, key ? *key : nullptr);
    cng_log_blob("import", input, input_size);
    return status;
}

static ntstatus_t WINAPI hook_BCryptExportKey(bcrypt_handle_t key, bcrypt_handle_t export_key,
                                              LPCWSTR blob_type, unsigned char* output, ULONG output_size,
                                              ULONG* result_size, ULONG flags) {
    ntstatus_t status = g_bcrypt_export_key
        ? g_bcrypt_export_key(key, export_key, blob_type, output, output_size, result_size, flags)
        : (ntstatus_t)0xC0000002L;
    char type[128] = {};
    cng_wide_ascii(blob_type, type, sizeof(type));
    ULONG actual = result_size ? *result_size : 0;
    shim_log("[cng] BCryptExportKey type=%s flags=0x%lx status=0x%08lx result=%lu",
             type, (unsigned long)flags, (unsigned long)status, (unsigned long)actual);
    if (status >= 0 && output && actual) cng_log_blob("export", output, actual);
    return status;
}

static ntstatus_t WINAPI hook_BCryptCreateHash(bcrypt_handle_t algorithm, bcrypt_handle_t* hash,
                                               unsigned char* hash_object, ULONG hash_object_size,
                                               unsigned char* secret, ULONG secret_size, ULONG flags) {
    ntstatus_t status = g_bcrypt_create_hash
        ? g_bcrypt_create_hash(algorithm, hash, hash_object, hash_object_size, secret, secret_size, flags)
        : (ntstatus_t)0xC0000002L;
    shim_log("[cng] BCryptCreateHash flags=0x%lx status=0x%08lx hash=%p",
             (unsigned long)flags, (unsigned long)status, hash ? *hash : nullptr);
    return status;
}

static ntstatus_t WINAPI hook_BCryptHashData(bcrypt_handle_t hash, unsigned char* input,
                                             ULONG input_size, ULONG flags) {
    ntstatus_t status = g_bcrypt_hash_data
        ? g_bcrypt_hash_data(hash, input, input_size, flags) : (ntstatus_t)0xC0000002L;
    shim_log("[cng] BCryptHashData hash=%p flags=0x%lx status=0x%08lx",
             hash, (unsigned long)flags, (unsigned long)status);
    if (status >= 0) cng_log_blob("hash input", input, input_size);
    return status;
}

static ntstatus_t WINAPI hook_BCryptFinishHash(bcrypt_handle_t hash, unsigned char* output,
                                               ULONG output_size, ULONG flags) {
    ntstatus_t status = g_bcrypt_finish_hash
        ? g_bcrypt_finish_hash(hash, output, output_size, flags) : (ntstatus_t)0xC0000002L;
    shim_log("[cng] BCryptFinishHash hash=%p flags=0x%lx status=0x%08lx",
             hash, (unsigned long)flags, (unsigned long)status);
    if (status >= 0) cng_log_blob("hash output", output, output_size);
    return status;
}

static ntstatus_t WINAPI hook_BCryptSecretAgreement(bcrypt_handle_t private_key, bcrypt_handle_t public_key,
                                                     bcrypt_handle_t* secret, ULONG flags) {
    ntstatus_t status = g_bcrypt_secret_agreement
        ? g_bcrypt_secret_agreement(private_key, public_key, secret, flags) : (ntstatus_t)0xC0000002L;
    shim_log("[cng] BCryptSecretAgreement flags=0x%lx status=0x%08lx secret=%p",
             (unsigned long)flags, (unsigned long)status, secret ? *secret : nullptr);
    return status;
}

static ntstatus_t WINAPI hook_BCryptDeriveKey(bcrypt_handle_t secret, LPCWSTR kdf,
                                              BCryptBufferDesc* parameters, unsigned char* derived_key,
                                              ULONG derived_key_size, ULONG* result_size, ULONG flags) {
    ntstatus_t status = g_bcrypt_derive_key
        ? g_bcrypt_derive_key(secret, kdf, parameters, derived_key, derived_key_size, result_size, flags)
        : (ntstatus_t)0xC0000002L;
    char name[128] = {};
    cng_wide_ascii(kdf, name, sizeof(name));
    ULONG actual = result_size ? *result_size : 0;
    shim_log("[cng] BCryptDeriveKey kdf=%s flags=0x%lx params=%lu status=0x%08lx result=%lu",
             name, (unsigned long)flags, parameters ? (unsigned long)parameters->cBuffers : 0,
             (unsigned long)status, (unsigned long)actual);
    if (parameters && parameters->pBuffers && parameters->cBuffers <= 16 &&
        !IsBadReadPtr(parameters->pBuffers, parameters->cBuffers * sizeof(BCryptBuffer))) {
        for (ULONG i = 0; i < parameters->cBuffers; ++i) {
            shim_log("[cng]   KDF buffer[%lu] type=%lu len=%lu", (unsigned long)i,
                     (unsigned long)parameters->pBuffers[i].BufferType,
                     (unsigned long)parameters->pBuffers[i].cbBuffer);
        }
    }
    return status;
}

static ntstatus_t WINAPI hook_BCryptVerifySignature(bcrypt_handle_t key, void* padding,
                                                    unsigned char* hash, ULONG hash_size,
                                                    unsigned char* signature, ULONG signature_size,
                                                    ULONG flags) {
    ntstatus_t status = g_bcrypt_verify_signature
        ? g_bcrypt_verify_signature(key, padding, hash, hash_size, signature, signature_size, flags)
        : (ntstatus_t)0xC0000002L;
    shim_log("[cng] BCryptVerifySignature flags=0x%lx status=0x%08lx", (unsigned long)flags,
             (unsigned long)status);
    cng_log_blob("verify hash", hash, hash_size);
    cng_log_blob("verify signature", signature, signature_size);
    return status;
}

static void cng_log_login_payload(const char* operation, unsigned char* input, ULONG input_size,
                                  unsigned char* output, ULONG output_size, ULONG actual,
                                  unsigned char* iv, ULONG iv_size, ntstatus_t status) {
    if (!hook_config().trace_cng_payload || input_size > 512 || output_size > 1024) return;
    shim_log("[cng] %s candidate payload buffer input=%lu output=%lu result=%lu iv=%lu status=0x%08lx",
             operation, (unsigned long)input_size, (unsigned long)output_size,
             (unsigned long)actual, (unsigned long)iv_size, (unsigned long)status);
    if (status < 0) return;
    cng_log_blob("AES input", input, input_size);
    if (output && actual) cng_log_blob("AES output", output, actual);
    if (iv && iv_size) cng_log_blob("AES IV", iv, iv_size);
}

static ntstatus_t WINAPI hook_BCryptEncrypt(bcrypt_handle_t key, unsigned char* input, ULONG input_size,
                                            void* padding, unsigned char* iv, ULONG iv_size,
                                            unsigned char* output, ULONG output_size,
                                            ULONG* result_size, ULONG flags) {
    ntstatus_t status = g_bcrypt_encrypt
        ? g_bcrypt_encrypt(key, input, input_size, padding, iv, iv_size, output, output_size, result_size, flags)
        : (ntstatus_t)0xC0000002L;
    cng_log_login_payload("BCryptEncrypt", input, input_size, output, output_size,
                          result_size ? *result_size : 0, iv, iv_size, status);
    return status;
}

static ntstatus_t WINAPI hook_BCryptDecrypt(bcrypt_handle_t key, unsigned char* input, ULONG input_size,
                                            void* padding, unsigned char* iv, ULONG iv_size,
                                            unsigned char* output, ULONG output_size,
                                            ULONG* result_size, ULONG flags) {
    ntstatus_t status = g_bcrypt_decrypt
        ? g_bcrypt_decrypt(key, input, input_size, padding, iv, iv_size, output, output_size, result_size, flags)
        : (ntstatus_t)0xC0000002L;
    cng_log_login_payload("BCryptDecrypt", input, input_size, output, output_size,
                          result_size ? *result_size : 0, iv, iv_size, status);
    return status;
}

static void* cng_wrapper_for(const char* name, void* real) {
    struct Map { const char* name; void* hook; void** real_slot; };
    static const Map maps[] = {
        {"BCryptOpenAlgorithmProvider", (void*)&hook_BCryptOpenAlgorithmProvider, (void**)&g_bcrypt_open_algorithm},
        {"BCryptImportKeyPair",         (void*)&hook_BCryptImportKeyPair,         (void**)&g_bcrypt_import_key_pair},
        {"BCryptExportKey",              (void*)&hook_BCryptExportKey,              (void**)&g_bcrypt_export_key},
        {"BCryptCreateHash",             (void*)&hook_BCryptCreateHash,             (void**)&g_bcrypt_create_hash},
        {"BCryptHashData",               (void*)&hook_BCryptHashData,               (void**)&g_bcrypt_hash_data},
        {"BCryptFinishHash",             (void*)&hook_BCryptFinishHash,             (void**)&g_bcrypt_finish_hash},
        {"BCryptSecretAgreement",        (void*)&hook_BCryptSecretAgreement,        (void**)&g_bcrypt_secret_agreement},
        {"BCryptDeriveKey",              (void*)&hook_BCryptDeriveKey,              (void**)&g_bcrypt_derive_key},
        {"BCryptVerifySignature",        (void*)&hook_BCryptVerifySignature,        (void**)&g_bcrypt_verify_signature},
        {"BCryptEncrypt",                (void*)&hook_BCryptEncrypt,                (void**)&g_bcrypt_encrypt},
        {"BCryptDecrypt",                (void*)&hook_BCryptDecrypt,                (void**)&g_bcrypt_decrypt},
    };
    for (const auto& map : maps) {
        if (strcmp(name, map.name) != 0) continue;
        if (!*map.real_slot) *map.real_slot = real;
        shim_log("[cng] dynamically bound bcrypt!%s", name);
        return map.hook;
    }
    return nullptr;
}
}

FARPROC wrap_fc5_cng_symbol(HMODULE module, LPCSTR name, FARPROC resolved) {
    if (!resolved || !name || reinterpret_cast<uintptr_t>(name) <= 0xffff) return resolved;
    if (module != GetModuleHandleA("bcrypt.dll") ||
        (!hook_config().trace_cng && !hook_config().trace_cng_payload)) return resolved;
    if (void* wrapper = cng_wrapper_for(name, reinterpret_cast<void*>(resolved)))
        return reinterpret_cast<FARPROC>(wrapper);
    return resolved;
}
