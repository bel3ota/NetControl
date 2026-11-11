package dev.netcontrol.app.data

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Session material is sealed with an AES-256-GCM key held by the Android
 * Keystore. The ciphertext lives in private SharedPreferences; the raw token is
 * never written to disk.
 */
class SecureStore(context: Context) {
    private val prefs = context.getSharedPreferences("netcontrol.secure", Context.MODE_PRIVATE)

    fun save(server: String, token: String) {
        val payload = "$server\n$token"
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // Let Android Keystore generate the IV; it is stored alongside the
        // ciphertext and supplied again for decryption.
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val nonce = cipher.iv
        val encrypted = cipher.doFinal(payload.toByteArray(Charsets.UTF_8))
        val combined = nonce + encrypted
        prefs.edit().putString("session", Base64.encodeToString(combined, Base64.NO_WRAP)).apply()
    }

    fun load(): Pair<String, String>? {
        val encoded = prefs.getString("session", null) ?: return null
        return runCatching {
            val combined = Base64.decode(encoded, Base64.NO_WRAP)
            if (combined.size < 13) return null
            val nonce = combined.copyOfRange(0, 12)
            val ciphertext = combined.copyOfRange(12, combined.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, nonce))
            val plain = cipher.doFinal(ciphertext).toString(Charsets.UTF_8)
            val parts = plain.split('\n', limit = 2)
            if (parts.size != 2) null else parts[0] to parts[1]
        }.getOrNull()
    }

    fun clear() {
        prefs.edit().remove("session").apply()
    }

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    private companion object {
        const val ALIAS = "netcontrol.session"
    }
}
