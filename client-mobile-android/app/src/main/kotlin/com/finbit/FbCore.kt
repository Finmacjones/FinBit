package com.finbit

/**
 * Thin Kotlin facade over the JNI bridge in core-jni/src/jni_bridge.cpp.
 *
 * Every fb::core call goes through these `external fun` declarations.
 * The `libfb_core_jni.so` shared library is bundled into the APK for each
 * target ABI by the externalNativeBuild Gradle config; loading it is a
 * one-time `System.loadLibrary("fb_core_jni")` in the companion object.
 */
object FbCore {

    init {
        System.loadLibrary("fb_core_jni")
    }

    /** Generate a fresh Ed25519 identity and return its base32 fingerprint. */
    external fun generateIdentityFingerprint(): String

    /** XChaCha20-Poly1305 seal. Throws on invalid sizes. */
    external fun xchacha20Encrypt(
        key: ByteArray,    // 32 bytes
        nonce: ByteArray,  // 24 bytes
        plaintext: ByteArray,
        aad: ByteArray,
    ): ByteArray

    /** XChaCha20-Poly1305 open. Returns null on tag mismatch. */
    external fun xchacha20Decrypt(
        key: ByteArray,
        nonce: ByteArray,
        ciphertextWithTag: ByteArray,
        aad: ByteArray,
    ): ByteArray?

    /** True if the runtime CPU supports AES-NI (most modern arm64 + x86_64). */
    external fun aes256GcmSupported(): Boolean
}
