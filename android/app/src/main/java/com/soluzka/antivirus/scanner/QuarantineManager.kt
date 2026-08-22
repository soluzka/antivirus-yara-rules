package com.soluzka.antivirus.scanner

import android.content.Context
import java.io.File
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * Quarantine manager — moves threat files to an encrypted quarantine
 * directory so they can't execute or be accessed.
 */
class QuarantineManager(private val context: Context) {

    private val quarantineDir = File(context.filesDir, "quarantine").apply { mkdirs() }
    private val keyFile = File(context.filesDir, "quarantine.key")

    private val secretKey: SecretKey by lazy {
        if (keyFile.exists()) {
            SecretKeySpec(keyFile.readBytes(), "AES")
        } else {
            val kg = KeyGenerator.getInstance("AES")
            kg.init(256)
            val key = kg.generateKey()
            keyFile.writeBytes(key.encoded)
            key
        }
    }

    data class QuarantineEntry(
        val originalPath: String,
        val fileName: String,
        val threatName: String,
        val fileHash: String,
        val fileSize: Long,
        val quarantinedAt: Long
    )

    /**
     * Move a threat file into encrypted quarantine.
     */
    fun quarantine(file: File, threatName: String): Boolean {
        if (!file.exists()) return false
        try {
            val bytes = file.readBytes()
            val encrypted = encrypt(bytes)

            val hash = sha256(bytes)
            val quarantineName = "${hash.take(16)}.enc"
            val quarantinedFile = File(quarantineDir, quarantineName)
            quarantinedFile.writeBytes(encrypted)

            // Save metadata
            val metaFile = File(quarantineDir, "$quarantineName.meta")
            val entry = QuarantineEntry(
                originalPath = file.absolutePath,
                fileName = file.name,
                threatName = threatName,
                fileHash = hash,
                fileSize = file.length(),
                quarantinedAt = System.currentTimeMillis()
            )
            metaFile.writeText(entryToString(entry))

            // Delete original
            file.delete()
            return true
        } catch (e: Exception) {
            return false
        }
    }

    /**
     * List all quarantined files.
     */
    fun listQuarantine(): List<QuarantineEntry> {
        val entries = mutableListOf<QuarantineEntry>()
        val metaFiles = quarantineDir.listFiles { f -> f.name.endsWith(".meta") } ?: return emptyList()
        for (meta in metaFiles) {
            try {
                val text = meta.readText()
                entries.add(entryFromString(text))
            } catch (e: Exception) { }
        }
        return entries.sortedByDescending { it.quarantinedAt }
    }

    /**
     * Delete a quarantined file permanently.
     */
    fun delete(quarantineName: String): Boolean {
        val encFile = File(quarantineDir, quarantineName)
        val metaFile = File(quarantineDir, "$quarantineName.meta")
        var ok = true
        if (encFile.exists()) ok = encFile.delete() && ok
        if (metaFile.exists()) ok = metaFile.delete() && ok
        return ok
    }

    /**
     * Restore a quarantined file (decrypt and move back to original location).
     */
    fun restore(quarantineName: String): Boolean {
        val encFile = File(quarantineDir, quarantineName)
        val metaFile = File(quarantineDir, "$quarantineName.meta")
        if (!encFile.exists() || !metaFile.exists()) return false
        try {
            val entry = entryFromString(metaFile.readText())
            val encrypted = encFile.readBytes()
            val decrypted = decrypt(encrypted)
            val original = File(entry.originalPath)
            original.writeBytes(decrypted)
            encFile.delete()
            metaFile.delete()
            return true
        } catch (e: Exception) {
            return false
        }
    }

    fun getQuarantineCount(): Int {
        return quarantineDir.listFiles { f -> f.name.endsWith(".enc") }?.size ?: 0
    }

    private fun encrypt(data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv
        val encrypted = cipher.doFinal(data)
        return iv + encrypted
    }

    private fun decrypt(data: ByteArray): ByteArray {
        val iv = data.copyOfRange(0, 12)
        val encrypted = data.copyOfRange(12, data.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, javax.crypto.spec.GCMParameterSpec(128, iv))
        return cipher.doFinal(encrypted)
    }

    private fun sha256(data: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(data).joinToString("") { "%02x".format(it) }
    }

    private fun entryToString(e: QuarantineEntry): String {
        return "${e.originalPath}\n${e.fileName}\n${e.threatName}\n${e.fileHash}\n${e.fileSize}\n${e.quarantinedAt}"
    }

    private fun entryFromString(s: String): QuarantineEntry {
        val parts = s.split("\n")
        return QuarantineEntry(
            originalPath = parts.getOrElse(0) { "" },
            fileName = parts.getOrElse(1) { "" },
            threatName = parts.getOrElse(2) { "" },
            fileHash = parts.getOrElse(3) { "" },
            fileSize = parts.getOrElse(4) { "0" }.toLongOrNull() ?: 0,
            quarantinedAt = parts.getOrElse(5) { "0" }.toLongOrNull() ?: 0
        )
    }
}
