// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/crypto/pq_kem.hpp"

#include <memory>

#if defined(FB_HAVE_ML_KEM) && FB_HAVE_ML_KEM
#  include <openssl/core_names.h>
#  include <openssl/err.h>
#  include <openssl/evp.h>
#endif

namespace fb::crypto::pq {

#if defined(FB_HAVE_ML_KEM) && FB_HAVE_ML_KEM

namespace {

// Pull the latest OpenSSL error onto a short string for PqError messages.
std::string openssl_err_msg() {
    char buf[256] = {0};
    if (unsigned long e = ERR_get_error(); e != 0) {
        ERR_error_string_n(e, buf, sizeof(buf));
        return std::string(buf);
    }
    return "<no openssl error>";
}

struct EvpPkeyDeleter      { void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); } };
struct EvpPkeyCtxDeleter   { void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); } };
using EvpPkeyPtr    = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;

EvpPkeyPtr import_pubkey(std::span<const std::uint8_t, kMlKem768PubBytes> raw) {
    EvpPkeyCtxPtr ctx{EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-768", nullptr)};
    if (!ctx) throw PqError("EVP_PKEY_CTX_new_from_name(ML-KEM-768): " + openssl_err_msg());
    if (EVP_PKEY_fromdata_init(ctx.get()) <= 0) {
        throw PqError("EVP_PKEY_fromdata_init: " + openssl_err_msg());
    }
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                          const_cast<std::uint8_t*>(raw.data()),
                                          kMlKem768PubBytes),
        OSSL_PARAM_construct_end(),
    };
    EVP_PKEY* pk_raw = nullptr;
    if (EVP_PKEY_fromdata(ctx.get(), &pk_raw, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        throw PqError("EVP_PKEY_fromdata(pub): " + openssl_err_msg());
    }
    return EvpPkeyPtr{pk_raw};
}

EvpPkeyPtr import_seckey(std::span<const std::uint8_t, kMlKem768SecBytes> raw) {
    EvpPkeyCtxPtr ctx{EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-768", nullptr)};
    if (!ctx) throw PqError("EVP_PKEY_CTX_new_from_name(ML-KEM-768): " + openssl_err_msg());
    if (EVP_PKEY_fromdata_init(ctx.get()) <= 0) {
        throw PqError("EVP_PKEY_fromdata_init: " + openssl_err_msg());
    }
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                          const_cast<std::uint8_t*>(raw.data()),
                                          kMlKem768SecBytes),
        OSSL_PARAM_construct_end(),
    };
    EVP_PKEY* pk_raw = nullptr;
    if (EVP_PKEY_fromdata(ctx.get(), &pk_raw, EVP_PKEY_KEYPAIR, params) <= 0) {
        throw PqError("EVP_PKEY_fromdata(priv): " + openssl_err_msg());
    }
    return EvpPkeyPtr{pk_raw};
}

}  // namespace

bool ml_kem_768_available() noexcept {
    EvpPkeyCtxPtr ctx{EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-768", nullptr)};
    return ctx != nullptr;
}

namespace {

MlKem768Keypair keygen_from_pkey(EvpPkeyPtr pkey) {
    MlKem768Keypair kp{};
    std::size_t pub_len = kMlKem768PubBytes;
    std::size_t sec_len = kMlKem768SecBytes;
    if (EVP_PKEY_get_octet_string_param(pkey.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                         kp.pub.data(), kp.pub.size(), &pub_len) <= 0) {
        throw PqError("EVP_PKEY_get_octet_string_param(pub): " + openssl_err_msg());
    }
    if (pub_len != kMlKem768PubBytes) {
        throw PqError("ML-KEM-768 pub length unexpected");
    }
    if (EVP_PKEY_get_octet_string_param(pkey.get(), OSSL_PKEY_PARAM_PRIV_KEY,
                                         kp.sec.data(), kp.sec.size(), &sec_len) <= 0) {
        throw PqError("EVP_PKEY_get_octet_string_param(priv): " + openssl_err_msg());
    }
    if (sec_len != kMlKem768SecBytes) {
        throw PqError("ML-KEM-768 sec length unexpected");
    }
    return kp;
}

}  // namespace

MlKem768Keypair keygen_ml_kem_768() {
    EvpPkeyCtxPtr ctx{EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-768", nullptr)};
    if (!ctx) throw PqError("EVP_PKEY_CTX_new_from_name(ML-KEM-768): " + openssl_err_msg());
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        throw PqError("EVP_PKEY_keygen_init: " + openssl_err_msg());
    }
    EVP_PKEY* pkey_raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &pkey_raw) <= 0) {
        throw PqError("EVP_PKEY_keygen(ML-KEM-768): " + openssl_err_msg());
    }
    return keygen_from_pkey(EvpPkeyPtr{pkey_raw});
}

MlKem768Keypair keygen_ml_kem_768_from_seed(
    std::span<const std::uint8_t, kMlKem768SeedBytes> seed) {
    EvpPkeyCtxPtr ctx{EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-768", nullptr)};
    if (!ctx) throw PqError("EVP_PKEY_CTX_new_from_name(ML-KEM-768): " + openssl_err_msg());
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        throw PqError("EVP_PKEY_keygen_init: " + openssl_err_msg());
    }
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_octet_string(
        "seed",
        const_cast<std::uint8_t*>(seed.data()),
        kMlKem768SeedBytes);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_CTX_set_params(ctx.get(), params) <= 0) {
        throw PqError("EVP_PKEY_CTX_set_params(seed): " + openssl_err_msg());
    }
    EVP_PKEY* pkey_raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &pkey_raw) <= 0) {
        throw PqError("EVP_PKEY_keygen(ML-KEM-768, seeded): " + openssl_err_msg());
    }
    return keygen_from_pkey(EvpPkeyPtr{pkey_raw});
}

MlKem768Encap encap_ml_kem_768(std::span<const std::uint8_t, kMlKem768PubBytes> peer_pub) {
    EvpPkeyPtr pkey = import_pubkey(peer_pub);
    EvpPkeyCtxPtr ctx{EVP_PKEY_CTX_new_from_pkey(nullptr, pkey.get(), nullptr)};
    if (!ctx) throw PqError("EVP_PKEY_CTX_new_from_pkey: " + openssl_err_msg());
    if (EVP_PKEY_encapsulate_init(ctx.get(), nullptr) <= 0) {
        throw PqError("EVP_PKEY_encapsulate_init: " + openssl_err_msg());
    }
    MlKem768Encap out{};
    std::size_t ct_len = kMlKem768CtBytes;
    std::size_t ss_len = kMlKem768SsBytes;
    if (EVP_PKEY_encapsulate(ctx.get(),
                              out.ct.data(), &ct_len,
                              out.ss.data(), &ss_len) <= 0) {
        throw PqError("EVP_PKEY_encapsulate: " + openssl_err_msg());
    }
    if (ct_len != kMlKem768CtBytes || ss_len != kMlKem768SsBytes) {
        throw PqError("ML-KEM-768 encap output size mismatch");
    }
    return out;
}

MlKem768Ss decap_ml_kem_768(std::span<const std::uint8_t, kMlKem768CtBytes> ct,
                            std::span<const std::uint8_t, kMlKem768SecBytes> my_sec) {
    EvpPkeyPtr pkey = import_seckey(my_sec);
    EvpPkeyCtxPtr ctx{EVP_PKEY_CTX_new_from_pkey(nullptr, pkey.get(), nullptr)};
    if (!ctx) throw PqError("EVP_PKEY_CTX_new_from_pkey: " + openssl_err_msg());
    if (EVP_PKEY_decapsulate_init(ctx.get(), nullptr) <= 0) {
        throw PqError("EVP_PKEY_decapsulate_init: " + openssl_err_msg());
    }
    MlKem768Ss ss{};
    std::size_t ss_len = kMlKem768SsBytes;
    if (EVP_PKEY_decapsulate(ctx.get(),
                              ss.data(), &ss_len,
                              ct.data(), ct.size()) <= 0) {
        throw PqError("EVP_PKEY_decapsulate: " + openssl_err_msg());
    }
    if (ss_len != kMlKem768SsBytes) {
        throw PqError("ML-KEM-768 decap output size mismatch");
    }
    return ss;
}

#else  // FB_HAVE_ML_KEM not defined

namespace {
[[noreturn]] void unavailable() {
    throw PqError("ML-KEM-768 unavailable: rebuild against OpenSSL 3.5+ "
                  "(FB_HAVE_ML_KEM=1)");
}
}  // namespace

bool ml_kem_768_available() noexcept { return false; }

MlKem768Keypair keygen_ml_kem_768() { unavailable(); }

MlKem768Keypair keygen_ml_kem_768_from_seed(
    std::span<const std::uint8_t, kMlKem768SeedBytes>) {
    unavailable();
}

MlKem768Encap encap_ml_kem_768(std::span<const std::uint8_t, kMlKem768PubBytes>) {
    unavailable();
}

MlKem768Ss decap_ml_kem_768(std::span<const std::uint8_t, kMlKem768CtBytes>,
                            std::span<const std::uint8_t, kMlKem768SecBytes>) {
    unavailable();
}

#endif

}  // namespace fb::crypto::pq
