# client-mobile-android

FinBit Android client. Kotlin + Jetpack Compose UI calling into `fb::core`
through a JNI bridge that compiles per-ABI via the Android NDK.

## Status

**Phase 1 scaffold — runnable today** for the crypto half (identity +
XChaCha20-Poly1305 self-test) once the NDK + libsodium-android are
installed. Networking, channels, and the in-band invite flow plug in next
through the same JNI surface.

## Prereqs

```bash
# 1. Android Studio + SDK + NDK (one-time)
#    Use Android Studio's SDK Manager OR install just the CLI:
sdkmanager "platforms;android-35" "build-tools;35.0.0" "ndk;26.3.11579264"

# 2. Tell the build where the NDK lives
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/26.3.11579264

# 3. Build libsodium for all three ABIs (one-time)
#    (clones libsodium 1.0.21 if not already present)
scripts/build-libsodium-android.sh
```

## Build

```bash
cd client-mobile-android
./gradlew assembleDebug
# APK at app/build/outputs/apk/debug/app-debug.apk
```

`./gradlew installDebug` deploys to a connected device or emulator.

## Architecture

```
client-mobile-android/
├── app/
│   ├── build.gradle.kts                 # Compose + NDK config, abiFilters
│   ├── src/main/
│   │   ├── AndroidManifest.xml
│   │   └── kotlin/com/finbit/
│   │       ├── FbCore.kt                # external fun bindings
│   │       └── MainActivity.kt          # Compose UI
│   └── ...
├── core-jni/
│   ├── CMakeLists.txt                   # cross-compiles fb::crypto + JNI shim
│   │                                    # against libsodium-android per ABI
│   └── src/jni_bridge.cpp               # extern "C" JNIEXPORT wrappers
├── settings.gradle.kts
├── build.gradle.kts
└── gradle.properties
```

## What's exposed via JNI today

`com.finbit.FbCore`:
- `generateIdentityFingerprint() : String`
  Generates a fresh Ed25519 identity, returns its `XXXXX-XXXXX` fingerprint.
- `xchacha20Encrypt(key, nonce, pt, aad) : ByteArray`
- `xchacha20Decrypt(key, nonce, ct, aad) : ByteArray?`  (null on tag mismatch)
- `aes256GcmSupported() : Boolean`

The Compose `MainActivity` exercises both — tap "Generate identity" and
"Run AEAD self-test" to verify the JNI bridge is wired correctly.

## What's not yet wired

- TCP networking through JNI. The fb_core net layer (epoll-based)
  needs a thin Android-side adapter; coming next.
- SQLite store. Android ships sqlite3 in the system; the JNI build
  picks it up via `-lsqlite` once we extend `core-jni/CMakeLists.txt`.
- Channel UI / DMs / safety-numbers. Same Compose patterns as
  `MainActivity`, just more `external fun` bindings + screens.
- Push notifications via FCM (decrypt opaque blob in NSE-equivalent).

## Mesh bridge on Android

USB-serial: `usb-serial-for-android` library + a small UsbDeviceConnection
JNI shim. BLE-serial bridge (Heltec/RAK boards over Bluetooth LE) goes
through the platform Bluetooth APIs.

MQTT: Paho's Java client (no native dep).

## Push notifications

FCM delivers opaque ciphertext blobs. The notification handler wakes the
process, calls into `fb::core` via JNI to decrypt, then posts a system
notification with the resulting plaintext. The FCM payload itself
contains no plaintext content. The full privacy design (what the push
provider can and can't infer, and how FinBit minimises it) is pre-locked
in [`docs/push-notifications.md`](../docs/push-notifications.md).

## Verification

The test scaffolding for `fb::core` itself runs on Linux (`ctest`); the
JNI surface is an `extern "C"` boundary that doesn't add testable logic
beyond marshalling. A small instrumented test under
`app/src/androidTest/` will cover the JNI roundtrip on a real device or
emulator once the network APIs land.
