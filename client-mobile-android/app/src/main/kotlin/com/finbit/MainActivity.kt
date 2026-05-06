package com.finbit

import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import kotlin.random.Random

/**
 * FinBit Phase-1 Android scaffold.
 *
 * Today this is intentionally a self-contained crypto smoke screen — it
 * doesn't talk to the relay yet. Tap "Generate identity" to prove the JNI
 * bridge into `fb::core` works (sodium init + Ed25519 keygen + base32
 * fingerprint). Tap "Run AEAD self-test" to round-trip a string through
 * XChaCha20-Poly1305 and back.
 *
 * Networking, storage, and the in-band channel UI plug in next via the
 * same JNI surface that already drives identity + AEAD.
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { FinBitApp() }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FinBitApp() {
    val log = remember { mutableStateListOf<String>() }
    val fingerprint = remember { mutableStateOf<String?>(null) }
    val aesSupported = remember { mutableStateOf(FbCore.aes256GcmSupported()) }

    Scaffold(topBar = { TopAppBar(title = { Text("FinBit") }) }) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .padding(16.dp)
                .fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("AES-NI on this device: ${if (aesSupported.value) "yes" else "no (XChaCha fallback)"}")

            Button(onClick = {
                val fp = FbCore.generateIdentityFingerprint()
                fingerprint.value = fp
                log.add(0, "identity: $fp")
            }, modifier = Modifier.fillMaxWidth()) {
                Text("Generate identity")
            }
            fingerprint.value?.let {
                Text("Fingerprint: $it", fontFamily = FontFamily.Monospace)
            }

            Button(onClick = {
                val key   = Random.nextBytes(32)
                val nonce = Random.nextBytes(24)
                val pt    = "hello from android".toByteArray(Charsets.UTF_8)
                val aad   = "extra-aad".toByteArray(Charsets.UTF_8)
                try {
                    val ct = FbCore.xchacha20Encrypt(key, nonce, pt, aad)
                    val rt = FbCore.xchacha20Decrypt(key, nonce, ct, aad)
                        ?: error("decrypt returned null")
                    val ok = rt.contentEquals(pt)
                    log.add(0, "aead self-test: ${if (ok) "OK (${ct.size}B ct)" else "MISMATCH"}")
                } catch (e: Throwable) {
                    log.add(0, "aead self-test: ${e.message}")
                }
            }, modifier = Modifier.fillMaxWidth()) {
                Text("Run AEAD self-test (XChaCha20-Poly1305)")
            }

            Divider()
            Text("Activity log", style = MaterialTheme.typography.titleSmall)
            LazyColumn(modifier = Modifier.weight(1f).fillMaxWidth()) {
                items(log) { line ->
                    Text(line, fontFamily = FontFamily.Monospace,
                         modifier = Modifier.padding(vertical = 4.dp))
                }
            }
        }
    }
}
