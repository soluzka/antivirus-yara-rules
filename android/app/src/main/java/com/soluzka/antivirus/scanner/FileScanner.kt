package com.soluzka.antivirus.scanner

import android.content.Context
import android.os.Build
import android.os.Environment
import android.os.StatFs
import android.provider.MediaStore
import android.util.Log
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
        val isComplete: Boolean,
        val threats: List<ScanResult> = emptyList()
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

    companion object {
        private const val TAG = "FileScanner"
    }

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
        val threatList = mutableListOf<ScanResult>()

        for (file in files) {
            val result = scanFile(file)
            scanned++
            if (result.isThreat) threatList.add(result)

            emit(ScanProgress(
                scannedFiles = scanned,
                totalFiles = total,
                threatsFound = threatList.size,
                currentFile = file.name,
                isComplete = false,
                threats = threatList.toList()
            ))
        }

        emit(ScanProgress(
            scannedFiles = scanned,
            totalFiles = total,
            threatsFound = threatList.size,
            currentFile = "",
            isComplete = true,
            threats = threatList.toList()
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
     * Full scan — entire external storage when accessible, otherwise
     * falls back to MediaStore-based collection and app-private directories.
     */
    fun fullScan(): Flow<ScanProgress> = flow {
        val allFiles = mutableListOf<File>()
        val dirs = mutableListOf<File>()

        val external = Environment.getExternalStorageDirectory()
        val canReadExternal = Build.VERSION.SDK_INT < Build.VERSION_CODES.R ||
            Environment.isExternalStorageManager()

        Log.i(TAG, "Full scan starting. canReadExternal=$canReadExternal, external=${external.absolutePath}")

        if (canReadExternal && external.exists()) {
            dirs.add(external)
        }

        // Always include app-private storage
        dirs.add(context.filesDir)
        dirs.add(context.cacheDir)
        dirs.add(context.getExternalFilesDir(null) ?: context.filesDir)

        // Collect files from File-accessible directories
        for (dir in dirs) {
            val files = collectFiles(dir)
            Log.i(TAG, "Collected ${files.size} files from ${dir.absolutePath}")
            allFiles.addAll(files)
        }

        // On Android 11+ with scoped storage, use MediaStore to find files
        // that aren't accessible via File APIs. This is the key fix —
        // without this, full scan finds almost nothing on modern Android.
        if (!canReadExternal || allFiles.size < 50) {
            Log.i(TAG, "Using MediaStore to collect additional files...")
            val mediaStoreFiles = collectFilesViaMediaStore()
            Log.i(TAG, "MediaStore returned ${mediaStoreFiles.size} files")
            val existingPaths = allFiles.map { it.absolutePath }.toHashSet()
            for (f in mediaStoreFiles) {
                if (f.absolutePath !in existingPaths) {
                    allFiles.add(f)
                }
            }
        }

        Log.i(TAG, "Total files to scan: ${allFiles.size}")

        val total = allFiles.size
        var scanned = 0
        val threatList = mutableListOf<ScanResult>()

        if (total == 0) {
            emit(ScanProgress(
                scannedFiles = 0,
                totalFiles = 0,
                threatsFound = 0,
                currentFile = "No accessible files to scan. Grant All Files Access in Settings for full scan.",
                isComplete = true
            ))
            return@flow
        }

        for (file in allFiles) {
            try {
                val result = scanFile(file)
                scanned++
                if (result.isThreat) threatList.add(result)

                emit(ScanProgress(
                    scannedFiles = scanned,
                    totalFiles = total,
                    threatsFound = threatList.size,
                    currentFile = file.name,
                    isComplete = false,
                    threats = threatList.toList()
                ))
            } catch (e: Exception) {
                Log.w(TAG, "Failed to scan ${file.absolutePath}: ${e.message}")
                scanned++
                emit(ScanProgress(
                    scannedFiles = scanned,
                    totalFiles = total,
                    threatsFound = threatList.size,
                    currentFile = file.name,
                    isComplete = false,
                    threats = threatList.toList()
                ))
            }
        }

        emit(ScanProgress(
            scannedFiles = scanned,
            totalFiles = total,
            threatsFound = threatList.size,
            currentFile = "",
            isComplete = true,
            threats = threatList.toList()
        ))
    }.flowOn(Dispatchers.IO)

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
        val threatList = mutableListOf<ScanResult>()

        if (total == 0) {
            emit(ScanProgress(
                scannedFiles = 0,
                totalFiles = 0,
                threatsFound = 0,
                currentFile = "No accessible files to scan",
                isComplete = true
            ))
            return@flow
        }

        for (file in allFiles) {
            val result = scanFile(file)
            scanned++
            if (result.isThreat) threatList.add(result)

            emit(ScanProgress(
                scannedFiles = scanned,
                totalFiles = total,
                threatsFound = threatList.size,
                currentFile = file.name,
                isComplete = false,
                threats = threatList.toList()
            ))
        }

        emit(ScanProgress(
            scannedFiles = scanned,
            totalFiles = total,
            threatsFound = threatList.size,
            currentFile = "",
            isComplete = true,
            threats = threatList.toList()
        ))
    }.flowOn(Dispatchers.IO)

    /**
     * Collect files via MediaStore ContentResolver. This works on Android 11+
     * with scoped storage where File APIs can't see media files.
     * Queries ALL file types, not just media.
     */
    private fun collectFilesViaMediaStore(): List<File> {
        val result = mutableListOf<File>()

        try {
            val projection = arrayOf(
                MediaStore.Files.FileColumns.DATA,
                MediaStore.Files.FileColumns.SIZE
            )
            // Query all files regardless of MIME type — malware can hide anywhere
            val selection = "${MediaStore.Files.FileColumns.SIZE} > 16 AND ${MediaStore.Files.FileColumns.SIZE} < $maxFileSize"
            val cursor = context.contentResolver.query(
                MediaStore.Files.getContentUri("external"),
                projection,
                selection,
                null,
                null
            ) ?: return result

            cursor.use { c ->
                val dataColumn = c.getColumnIndexOrThrow(MediaStore.Files.FileColumns.DATA)
                val sizeColumn = c.getColumnIndexOrThrow(MediaStore.Files.FileColumns.SIZE)
                while (c.moveToNext()) {
                    val path = c.getString(dataColumn) ?: continue
                    val size = c.getLong(sizeColumn)
                    if (size < 16 || size > maxFileSize) continue
                    val file = File(path)
                    if (file.exists() && file.isFile && file.canRead()) {
                        result.add(file)
                    }
                }
            }
            Log.i(TAG, "MediaStore query returned ${result.size} files")
        } catch (e: Exception) {
            Log.w(TAG, "MediaStore collection failed: ${e.message}")
        }
        return result
    }

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
            Log.w(TAG, "collectFiles failed for ${dir.absolutePath}: ${e.message}")
        }
        return result
    }

    private fun shouldScan(file: File): Boolean {
        if (file.length() > maxFileSize) return false
        if (file.length() < 16) return false  // Too small to be meaningful
        // Full scan scans ALL files regardless of extension.
        // Malware can hide in any file type (images, audio, documents, etc.)
        return true
    }
}
