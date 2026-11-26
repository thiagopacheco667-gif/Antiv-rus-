package com.aegis.security.domain.repository

import com.aegis.security.domain.model.FileHashes
import com.aegis.security.domain.model.FileMetadata
import java.io.File
import java.io.IOException
import java.io.InputStream

/** Arquivo copiado para o armazenamento privado do app, com hashes calculados na cópia. */
data class StagedFile(val file: File, val sizeBytes: Long, val hashes: FileHashes)

class FileAccessException(message: String, cause: Throwable? = null) : IOException(message, cause)

class FileTooLargeException(val limitBytes: Long) : IOException("Arquivo maior que o limite de $limitBytes bytes")

/**
 * Acesso a arquivos escolhidos pelo usuário (Storage Access Framework).
 * Os arquivos são lidos em blocos e nunca executados.
 */
interface FileStager {
    @Throws(FileAccessException::class)
    suspend fun describe(uri: String): FileMetadata

    @Throws(FileAccessException::class)
    suspend fun readHeader(uri: String, maxBytes: Int): ByteArray

    /**
     * Copia para o cache privado calculando SHA-256, SHA-1 e MD5 em uma única leitura.
     * [onProgress] recebe os bytes lidos até o momento.
     */
    @Throws(FileAccessException::class, FileTooLargeException::class)
    suspend fun stage(uri: String, maxBytes: Long, onProgress: suspend (Long) -> Unit): StagedFile

    fun release(staged: StagedFile)

    @Throws(FileAccessException::class)
    fun open(uri: String): InputStream
}
