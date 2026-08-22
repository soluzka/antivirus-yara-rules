package com.soluzka.antivirus.scanner

import android.content.Context
import android.os.Environment
import android.os.StatFs
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import java.io.File

/**
 * Scans files on the Android device for malware using YARA rules
 * and ML classification.
 */
class FileScanner(
    private val context: Context,
    private val yaraScanner: YaraScanner,
    private val mlScanner: MlScanner
) {

    data class ScanResult(
        val file: File,
        val fileSize: Long,
        val yaraMatches: List<YaraScanner.YaraMatch>,
        val mlResult: MlScanner.MlResult?,
        val isThreat: Boolean,
        val threatName: String,
        val severity: String  // "high", "medium", "low", "clean"
    )

    data class ScanProgress(
        val scannedFiles: Int,
        val totalFiles: Int,
        val threatsFound: Int,
        val currentFile: String,
        val isComplete: Boolean
    )

    // File extensions worth scanning
    private val scanExtensions = setOf(
        "apk", "dex", "jar", "zip", "rar", "7z",
        "exe", "dll", "sys", "so", "bin",
        "pdf", "doc", "docx", "xls", "xlsx",
        "js", "vbs", "ps1", "bat", "cmd", "sh",
        "elf", "dat", "db", "tmp"
    )

    private val maxFileSize = 50L * 1024 * 1024  // 50 MB limit per file

    /**
     * Scan a single file.
     */
    fun scanFile(file: File): ScanResult {
        val yaraMatches = yaraScanner.scanFile(file)
        val mlResult = if (mlScanner.isLoaded()) mlScanner.classifyFile(file) else null

        val isThreat = yaraMatches.isNotEmpty() || (mlResult?.isMalicious == true)
        val threatName = when {
            yaraMatches.isNotEmpty() -> yaraMatches.first().ruleName
            mlResult?.isMalicious == true -> "ML:Malware"
            else -> "Clean"
        }
        val severity = when {
            yaraMatches.any { it.tags.contains("ransomware") || it.tags.contains("trojan") } -> "high"
            yaraMatches.isNotEmpty() -> "medium"
            mlResult?.isMalicious == true && (mlResult.confidence > 0.8f) -> "high"
            mlResult?.isMalicious == true -> "medium"
            else -> "clean"
        }

        return ScanResult(
            file = file,
            fileSize = file.length(),
            yaraMatches = yaraMatches,
            mlResult = mlResult,
            isThreat = isThreat,
            threatName = threatName,
            severity = severity
        )
    }

    /**
     * Scan all files in a directory, emitting progress updates.
     */
    fun scanDirectory(rootDir: File): Flow<ScanProgress> = flow {
        val files = collectFiles(rootDir)
        val total = files.size
        var scanned = 0
        var threats = 0

        for (file in files) {
            val result = scanFile(file)
            scanned++
            if (result.isThreat) threats++

            emit(ScanProgress(
                scannedFiles = scanned,
                totalFiles = total,
                threatsFound = threats,
                currentFile = file.name,
                isComplete = false
            ))
        }

        emit(ScanProgress(
            scannedFiles = scanned,
            totalFiles = total,
            threatsFound = threats,
            currentFile = "",
            isComplete = true
        ))
    }.flowOn(Dispatchers.IO)

    /**
     * Quick scan — only common download locations.
     */
    fun quickScan(): Flow<ScanProgress> {
        val downloadDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        val docDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS)
        val dirs = mutableListOf<File>()
        if (downloadDir.exists()) dirs.add(downloadDir)
        if (docDir.exists()) dirs.add(docDir)
        // Also scan app-private storage
        dirs.add(context.filesDir)
        dirs.add(context.cacheDir)
        return scanDirectories(dirs)
    }

    /**
     * Full scan — entire external storage.
     */
    fun fullScan(): Flow<ScanProgress> {
        val external = Environment.getExternalStorageDirectory()
        return scanDirectory(external)
    }

    /**
     * Scan multiple directories.
     */
    fun scanDirectories(dirs: List<File>): Flow<ScanProgress> = flow {
        val allFiles = mutableListOf<File>()
        for (dir in dirs) {
            allFiles.addAll(collectFiles(dir))
        }
        val total = allFiles.size
        var scanned = 0
        var threats = 0

        for (file in allFiles) {
            val result = scanFile(file)
            scanned++
            if (result.isThreat) threats++

            emit(ScanProgress(
                scannedFiles = scanned,
                totalFiles = total,
                threatsFound = threats,
                currentFile = file.name,
                isComplete = false
            ))
        }

        emit(ScanProgress(
            scannedFiles = scanned,
            totalFiles = total,
            threatsFound = threats,
            currentFile = "",
            isComplete = true
        ))
    }.flowOn(Dispatchers.IO)

    /**
     * Recursively collect files worth scanning.
     */
    private fun collectFiles(dir: File): List<File> {
        val result = mutableListOf<File>()
        if (!dir.exists() || !dir.isDirectory) return result

        try {
            dir.walkTopDown().forEach { file ->
                if (file.isFile && shouldScan(file)) {
                    result.add(file)
                }
            }
        } catch (e: Exception) {
            // Permission denied or similar — skip
        }
        return result
    }

    private fun shouldScan(file: File): Boolean {
        if (file.length() > maxFileSize) return false
        if (file.length() < 16) return false  // Too small to be meaningful
        val ext = file.extension.lowercase()
        return ext.isEmpty() || ext in scanExtensions
    }
}
