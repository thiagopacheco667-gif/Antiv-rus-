package com.aegis.security.data.local

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import com.aegis.security.core.common.dispatchers.AegisDispatchers
import com.aegis.security.core.common.dispatchers.Dispatcher
import com.aegis.security.domain.model.FileHashes
import com.aegis.security.domain.model.FileMetadata
import com.aegis.security.domain.repository.FileAccessException
import com.aegis.security.domain.repository.FileStager
import com.aegis.security.domain.repository.FileTooLargeException
import com.aegis.security.domain.repository.StagedFile
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest
import java.util.UUID
import javax.inject.Inject

/**
 * Acesso a arquivos via Storage Access Framework: somente o arquivo escolhido pelo usuário,
 * sem permissão de armazenamento amplo. A cópia de trabalho fica em `cacheDir/scan` (privado),
 * os hashes são calculados durante a cópia em blocos de 64 KB e nada é executado.
 */
internal class SafFileStager @Inject constructor(
    @ApplicationContext private val context: Context,
    @Dispatcher(AegisDispatchers.IO) private val io: CoroutineDispatcher,
) : FileStager {
    private val resolver: ContentResolver get() = context.contentResolver
    private val scanDir: File get() = File(context.cacheDir, "scan").apply { mkdirs() }

    override suspend fun describe(uri: String): FileMetadata = withContext(io) {
        val parsed = Uri.parse(uri)
        guard {
            var name: String? = null
            var size: Long? = null
            var modified: Long? = null
            resolver.query(parsed, null, null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME).takeIf { it >= 0 && !cursor.isNull(it) }?.let { name = cursor.getString(it) }
                    cursor.getColumnIndex(OpenableColumns.SIZE).takeIf { it >= 0 && !cursor.isNull(it) }?.let { size = cursor.getLong(it) }
                    cursor.getColumnIndex(DocumentsContract.Document.COLUMN_LAST_MODIFIED)
                        .takeIf { it >= 0 && !cursor.isNull(it) }?.let { modified = cursor.getLong(it).takeIf { v -> v > 0 } }
                }
            } ?: throw FileAccessException("o provedor não retornou informações do arquivo")
            val displayName = name ?: parsed.lastPathSegment ?: "arquivo"
            FileMetadata(
                fileName = displayName,
                declaredExtension = displayName.substringAfterLast('.', "").lowercase().takeIf { displayName.contains('.') && it.isNotBlank() && it.length <= 10 },
                sizeBytes = size?.takeIf { it >= 0 },
                mimeType = resolver.getType(parsed),
                lastModifiedEpochMillis = modified,
                provider = providerLabel(parsed.authority),
            )
        }
    }

    override suspend fun readHeader(uri: String, maxBytes: Int): ByteArray = withContext(io) {
        open(uri).use { input ->
            val buffer = ByteArray(maxBytes)
            var read = 0
            while (read < maxBytes) {
                val n = input.read(buffer, read, maxBytes - read)
                if (n < 0) break
                read += n
            }
            buffer.copyOf(read)
        }
    }

    override suspend fun stage(uri: String, maxBytes: Long, onProgress: suspend (Long) -> Unit): StagedFile = withContext(io) {
        cleanupStale()
        val target = File(scanDir, "${UUID.randomUUID()}.bin")
        val sha256 = MessageDigest.getInstance("SHA-256")
        val sha1 = MessageDigest.getInstance("SHA-1")
        val md5 = MessageDigest.getInstance("MD5")
        var total = 0L
        try {
            open(uri).use { input ->
                FileOutputStream(target).use { output ->
                    val buffer = ByteArray(BUFFER_SIZE)
                    while (true) {
                        currentCoroutineContext().ensureActive()
                        val n = input.read(buffer)
                        if (n < 0) break
                        total += n
                        if (total > maxBytes) throw FileTooLargeException(maxBytes)
                        sha256.update(buffer, 0, n)
                        sha1.update(buffer, 0, n)
                        md5.update(buffer, 0, n)
                        output.write(buffer, 0, n)
                        onProgress(total)
                    }
                }
            }
            StagedFile(target, total, FileHashes(hex(sha256.digest()), hex(sha1.digest()), hex(md5.digest())))
        } catch (error: Throwable) {
            target.delete()
            if (error is SecurityException) throw FileAccessException("permissão de leitura revogada", error)
            throw error
        }
    }

    override fun release(staged: StagedFile) {
        staged.file.delete()
    }

    override fun newWorkDir(): File = File(scanDir, "parts-${UUID.randomUUID()}").apply { mkdirs() }

    override fun deleteWorkDir(dir: File) {
        if (dir.parentFile == scanDir) dir.deleteRecursively()
    }

    override fun open(uri: String): InputStream = guard {
        resolver.openInputStream(Uri.parse(uri)) ?: throw FileAccessException("o provedor não abriu o arquivo")
    }

    /** Remove cópias de análises interrompidas (ex.: processo encerrado). */
    private fun cleanupStale() {
        val cutoff = System.currentTimeMillis() - STALE_AFTER_MILLIS
        scanDir.listFiles()?.filter { it.lastModified() < cutoff }?.forEach { it.deleteRecursively() }
    }

    private inline fun <T> guard(block: () -> T): T = try {
        block()
    } catch (error: FileAccessException) {
        throw error
    } catch (error: SecurityException) {
        throw FileAccessException("sem permissão para ler o arquivo", error)
    } catch (error: FileNotFoundException) {
        throw FileAccessException("arquivo não encontrado ou inacessível", error)
    } catch (error: IllegalArgumentException) {
        throw FileAccessException("endereço de arquivo inválido", error)
    } catch (error: IOException) {
        throw FileAccessException(error.message ?: "falha de leitura", error)
    }

    private fun providerLabel(authority: String?): String? = when (authority) {
        null -> null
        "com.android.externalstorage.documents" -> "Armazenamento do aparelho"
        "com.android.providers.downloads.documents" -> "Downloads"
        "com.android.providers.media.documents" -> "Mídia"
        "com.google.android.apps.docs.storage" -> "Google Drive"
        else -> authority
    }

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }

    private companion object {
        const val BUFFER_SIZE = 64 * 1024
        const val STALE_AFTER_MILLIS = 60 * 60 * 1000L
    }
}
