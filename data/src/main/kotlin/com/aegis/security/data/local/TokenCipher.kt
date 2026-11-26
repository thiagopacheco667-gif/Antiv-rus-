package com.aegis.security.data.local

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.inject.Inject
import javax.inject.Singleton

/** Cifra configurações sensíveis antes de persistir. */
interface TokenCipher {
    fun encrypt(plain: String): String

    /** Retorna null se o valor não puder ser decifrado (ex.: chave removida pelo sistema). */
    fun decrypt(encoded: String): String?
}

/**
 * AES-256-GCM com chave não exportável no Android Keystore. O token de acesso ao backend
 * nunca é gravado em texto puro.
 */
@Singleton
internal class KeystoreTokenCipher @Inject constructor() : TokenCipher {

    override fun encrypt(plain: String): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(byteArrayOf(iv.size.toByte()) + iv + ciphertext, Base64.NO_WRAP)
    }

    override fun decrypt(encoded: String): String? = try {
        val data = Base64.decode(encoded, Base64.NO_WRAP)
        val ivLength = data[0].toInt()
        require(ivLength in 12..16 && data.size > 1 + ivLength)
        val iv = data.copyOfRange(1, 1 + ivLength)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG_BITS, iv))
        String(cipher.doFinal(data.copyOfRange(1 + ivLength, data.size)), Charsets.UTF_8)
    } catch (error: GeneralSecurityException) {
        null
    } catch (error: IllegalArgumentException) {
        null
    }

    private fun key(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (keyStore.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val ALIAS = "aegis_backend_token"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val TAG_BITS = 128
    }
}
