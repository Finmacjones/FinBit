// SPDX-License-Identifier: AGPL-3.0-or-later
// JNI bridge — extern "C" wrappers around fb::core for Kotlin's `external fun`
// declarations in app/src/main/kotlin/com/finbit/FbCore.kt.
//
// Conventions:
//   - JNI strings are returned via env->NewStringUTF (UTF-8).
//   - byte[] is wrapped via GetByteArrayElements / Release.
//   - C++ exceptions are caught and re-thrown as java/lang/RuntimeException
//     so the Kotlin side sees them as standard exceptions.

#include <jni.h>

#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include "fb/crypto/aead.hpp"
#include "fb/crypto/identity.hpp"

namespace {

void throw_runtime(JNIEnv* env, const std::string& msg) {
    jclass cls = env->FindClass("java/lang/RuntimeException");
    if (cls) env->ThrowNew(cls, msg.c_str());
}

std::vector<std::uint8_t> from_jbytes(JNIEnv* env, jbyteArray a) {
    if (!a) return {};
    const jsize n = env->GetArrayLength(a);
    std::vector<std::uint8_t> out(static_cast<std::size_t>(n));
    if (n > 0) env->GetByteArrayRegion(a, 0, n, reinterpret_cast<jbyte*>(out.data()));
    return out;
}

jbyteArray to_jbytes(JNIEnv* env, std::span<const std::uint8_t> b) {
    jbyteArray out = env->NewByteArray(static_cast<jsize>(b.size()));
    if (!out) return nullptr;
    if (!b.empty()) {
        env->SetByteArrayRegion(out, 0, static_cast<jsize>(b.size()),
                                reinterpret_cast<const jbyte*>(b.data()));
    }
    return out;
}

}  // namespace

extern "C" {

JNIEXPORT jstring JNICALL
Java_com_finbit_FbCore_generateIdentityFingerprint(JNIEnv* env, jobject /*self*/) {
    try {
        auto id = fb::crypto::Identity::generate();
        return env->NewStringUTF(id.fingerprint().c_str());
    } catch (const std::exception& e) {
        throw_runtime(env, std::string("identity gen: ") + e.what());
        return nullptr;
    }
}

JNIEXPORT jboolean JNICALL
Java_com_finbit_FbCore_aes256GcmSupported(JNIEnv* /*env*/, jobject /*self*/) {
    return fb::crypto::aes256gcm_hw_available() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jbyteArray JNICALL
Java_com_finbit_FbCore_xchacha20Encrypt(JNIEnv* env, jobject /*self*/, jbyteArray jkey,
                                         jbyteArray jnonce, jbyteArray jpt, jbyteArray jaad) {
    try {
        auto k = from_jbytes(env, jkey);
        auto n = from_jbytes(env, jnonce);
        if (k.size() != 32 || n.size() != 24) {
            throw_runtime(env, "xchacha20Encrypt: key=32B, nonce=24B required");
            return nullptr;
        }
        fb::crypto::AeadKey ak{};
        fb::crypto::XChaChaNonce xn{};
        std::memcpy(ak.data(), k.data(), 32);
        std::memcpy(xn.data(), n.data(), 24);
        auto pt = from_jbytes(env, jpt);
        auto aad = from_jbytes(env, jaad);
        auto ct = fb::crypto::xchacha20_encrypt(
            ak, xn,
            std::span<const std::uint8_t>(pt.data(), pt.size()),
            std::span<const std::uint8_t>(aad.data(), aad.size()));
        return to_jbytes(env, std::span<const std::uint8_t>(ct.data(), ct.size()));
    } catch (const std::exception& e) {
        throw_runtime(env, std::string("xchacha20Encrypt: ") + e.what());
        return nullptr;
    }
}

JNIEXPORT jbyteArray JNICALL
Java_com_finbit_FbCore_xchacha20Decrypt(JNIEnv* env, jobject /*self*/, jbyteArray jkey,
                                         jbyteArray jnonce, jbyteArray jct, jbyteArray jaad) {
    try {
        auto k = from_jbytes(env, jkey);
        auto n = from_jbytes(env, jnonce);
        if (k.size() != 32 || n.size() != 24) {
            throw_runtime(env, "xchacha20Decrypt: key=32B, nonce=24B required");
            return nullptr;
        }
        fb::crypto::AeadKey ak{};
        fb::crypto::XChaChaNonce xn{};
        std::memcpy(ak.data(), k.data(), 32);
        std::memcpy(xn.data(), n.data(), 24);
        auto ct = from_jbytes(env, jct);
        auto aad = from_jbytes(env, jaad);
        auto pt = fb::crypto::xchacha20_decrypt(
            ak, xn,
            std::span<const std::uint8_t>(ct.data(), ct.size()),
            std::span<const std::uint8_t>(aad.data(), aad.size()));
        if (!pt) return nullptr;  // Kotlin sees this as null, the documented "tag mismatch"
        return to_jbytes(env, std::span<const std::uint8_t>(pt->data(), pt->size()));
    } catch (const std::exception& e) {
        throw_runtime(env, std::string("xchacha20Decrypt: ") + e.what());
        return nullptr;
    }
}

}  // extern "C"
