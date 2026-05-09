// SPDX-License-Identifier: AGPL-3.0-or-later
#include "fb/crypto/identity_cert.hpp"

#include <memory>
#include <stdexcept>

#if FB_HAVE_OPENSSL

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

namespace fb::crypto {

namespace {

// RAII wrappers for the OpenSSL types we touch. Avoids leak / double-
// free bugs when an early throw skips the manual *_free call.
struct EvpKeyDeleter   { void operator()(EVP_PKEY* p) const { if (p) EVP_PKEY_free(p); } };
struct X509Deleter     { void operator()(X509* p)     const { if (p) X509_free(p); } };
struct BioDeleter      { void operator()(BIO* p)      const { if (p) BIO_free(p); } };
using EvpKeyPtr = std::unique_ptr<EVP_PKEY, EvpKeyDeleter>;
using X509Ptr   = std::unique_ptr<X509,     X509Deleter>;
using BioPtr    = std::unique_ptr<BIO,      BioDeleter>;

[[noreturn]] void throw_openssl(const std::string& what) {
    char buf[256] = {0};
    const auto err = ERR_get_error();
    if (err != 0) ERR_error_string_n(err, buf, sizeof(buf));
    else std::snprintf(buf, sizeof(buf), "(no OpenSSL error queued)");
    throw std::runtime_error("identity_cert " + what + ": " + buf);
}

}  // namespace

PemCertKey generate_identity_cert(
    std::span<const std::uint8_t, 32> identity_seed,
    int validity_days) {
    // Seed → EVP_PKEY (Ed25519). EVP_PKEY_new_raw_private_key takes
    // the 32-byte seed exactly; OpenSSL derives the matching public
    // key internally so the X.509 SubjectPublicKeyInfo is consistent.
    EvpKeyPtr pkey(EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr,
        identity_seed.data(), identity_seed.size()));
    if (!pkey) throw_openssl("EVP_PKEY_new_raw_private_key");

    X509Ptr cert(X509_new());
    if (!cert) throw_openssl("X509_new");

    if (X509_set_version(cert.get(), 2) != 1) throw_openssl("X509_set_version");

    // Serial: deterministic-but-arbitrary. We never present this cert
    // to a CA-validating verifier, so the value doesn't matter for
    // chain semantics.
    if (ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1) != 1) {
        throw_openssl("ASN1_INTEGER_set");
    }

    if (X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0) == nullptr) {
        throw_openssl("notBefore");
    }
    const long secs = static_cast<long>(validity_days) * 24 * 60 * 60;
    if (X509_gmtime_adj(X509_getm_notAfter(cert.get()), secs) == nullptr) {
        throw_openssl("notAfter");
    }

    if (X509_set_pubkey(cert.get(), pkey.get()) != 1) {
        throw_openssl("X509_set_pubkey");
    }

    // Subject + issuer are both "CN=FinBit-Identity". The CN is just
    // a human label — the load-bearing identity material is the
    // SubjectPublicKeyInfo, which IS the Ed25519 pubkey.
    X509_NAME* name = X509_get_subject_name(cert.get());
    if (X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>("FinBit-Identity"),
            -1, -1, 0) != 1) {
        throw_openssl("X509_NAME_add_entry_by_txt");
    }
    if (X509_set_issuer_name(cert.get(), name) != 1) {
        throw_openssl("X509_set_issuer_name");
    }

    // Sign with Ed25519. EdDSA does not use a separate digest — pass
    // nullptr for the EVP_MD argument; OpenSSL ≥ 1.1.1 handles the
    // pure-EdDSA signing path internally.
    if (X509_sign(cert.get(), pkey.get(), nullptr) == 0) {
        throw_openssl("X509_sign");
    }

    // PEM-encode both pieces.
    BioPtr cert_bio(BIO_new(BIO_s_mem()));
    if (!cert_bio || PEM_write_bio_X509(cert_bio.get(), cert.get()) != 1) {
        throw_openssl("PEM_write_bio_X509");
    }
    BUF_MEM* cm = nullptr;
    BIO_get_mem_ptr(cert_bio.get(), &cm);
    std::string cert_pem(cm->data, cm->length);

    BioPtr key_bio(BIO_new(BIO_s_mem()));
    if (!key_bio ||
        PEM_write_bio_PrivateKey(key_bio.get(), pkey.get(),
                                  nullptr, nullptr, 0,
                                  nullptr, nullptr) != 1) {
        throw_openssl("PEM_write_bio_PrivateKey");
    }
    BUF_MEM* km = nullptr;
    BIO_get_mem_ptr(key_bio.get(), &km);
    std::string key_pem(km->data, km->length);

    return {std::move(cert_pem), std::move(key_pem)};
}

std::optional<std::array<std::uint8_t, 32>>
extract_pubkey_from_cert_pem(const std::string& cert_pem) {
    BioPtr bio(BIO_new_mem_buf(cert_pem.data(),
                                static_cast<int>(cert_pem.size())));
    if (!bio) return std::nullopt;
    X509Ptr cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if (!cert) return std::nullopt;

    EvpKeyPtr pkey(X509_get_pubkey(cert.get()));
    if (!pkey) return std::nullopt;
    if (EVP_PKEY_id(pkey.get()) != EVP_PKEY_ED25519) return std::nullopt;

    std::array<std::uint8_t, 32> out{};
    std::size_t len = out.size();
    if (EVP_PKEY_get_raw_public_key(pkey.get(), out.data(), &len) != 1) {
        return std::nullopt;
    }
    if (len != 32) return std::nullopt;
    return out;
}

}  // namespace fb::crypto

#else   // FB_HAVE_OPENSSL == 0

namespace fb::crypto {

PemCertKey generate_identity_cert(
    std::span<const std::uint8_t, 32>, int) {
    throw std::runtime_error(
        "identity_cert: OpenSSL not compiled in. Rebuild with "
        "OpenSSL on the link line so FB_HAVE_OPENSSL=1.");
}

std::optional<std::array<std::uint8_t, 32>>
extract_pubkey_from_cert_pem(const std::string&) {
    return std::nullopt;
}

}  // namespace fb::crypto

#endif  // FB_HAVE_OPENSSL
