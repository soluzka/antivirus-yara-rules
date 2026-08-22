package com.soluzka.antivirus

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.soluzka.antivirus.scanner.FileScanner
import com.soluzka.antivirus.scanner.MlScanner
import com.soluzka.antivirus.scanner.QuarantineManager
import com.soluzka.antivirus.scanner.YaraScanner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ScannerFragment : Fragment() {

    private lateinit var yaraScanner: YaraScanner
    private lateinit var mlScanner: MlScanner
    private lateinit var fileScanner: FileScanner
    private lateinit var quarantine: QuarantineManager

    private lateinit var protectionStatus: TextView
    private lateinit var statusDetail: TextView
    private lateinit var lastScanText: TextView
    private lateinit var quickScanBtn: Button
    private lateinit var fullScanBtn: Button
    private lateinit var progressContainer: LinearLayout
    private lateinit var progressText: TextView
    private lateinit var scanProgressBar: ProgressBar
    private lateinit var progressDetail: TextView
    private lateinit var threatsHeader: TextView
    private lateinit var threatsList: RecyclerView
    private lateinit var quarantineCount: TextView
    private lateinit var quarantineList: RecyclerView

    private val threatsAdapter = ThreatAdapter()
    private val quarantineAdapter = QuarantineAdapter()
    private var isScanning = false

    companion object {
        private const val PERMISSION_REQUEST = 1001
        private const val MANAGE_STORAGE_REQUEST = 1002
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val view = inflater.inflate(R.layout.fragment_scanner, container, false)
        initViews(view)
        initScanners()
        requestPermissions()
        return view
    }

    private fun initViews(view: View) {
        protectionStatus = view.findViewById(R.id.protectionStatus)
        statusDetail = view.findViewById(R.id.statusDetail)
        lastScanText = view.findViewById(R.id.lastScanText)
        quickScanBtn = view.findViewById(R.id.quickScanBtn)
        fullScanBtn = view.findViewById(R.id.fullScanBtn)
        progressContainer = view.findViewById(R.id.progressContainer)
        progressText = view.findViewById(R.id.progressText)
        scanProgressBar = view.findViewById(R.id.scanProgressBar)
        progressDetail = view.findViewById(R.id.progressDetail)
        threatsHeader = view.findViewById(R.id.threatsHeader)
        threatsList = view.findViewById(R.id.threatsList)
        quarantineCount = view.findViewById(R.id.quarantineCount)
        quarantineList = view.findViewById(R.id.quarantineList)

        threatsList.layoutManager = LinearLayoutManager(context)
        threatsList.adapter = threatsAdapter

        quarantineList.layoutManager = LinearLayoutManager(context)
        quarantineList.adapter = quarantineAdapter

        quickScanBtn.setOnClickListener { startQuickScan() }
        fullScanBtn.setOnClickListener { startFullScan() }
    }

    private fun initScanners() {
        yaraScanner = YaraScanner(requireContext())
        yaraScanner.loadRulesFromAssets()

        mlScanner = MlScanner(requireContext())
        fileScanner = FileScanner(requireContext(), yaraScanner, mlScanner)
        quarantine = QuarantineManager(requireContext())

        updateStatus()
        refreshQuarantine()

        // Load ML models on a background thread — they're 35+ MB
        // and would freeze/crash the app if loaded on the main thread
        lifecycleScope.launch(Dispatchers.IO) {
            mlScanner.loadModels()
            withContext(Dispatchers.Main) {
                updateStatus()
            }
        }
    }

    private fun requestPermissions() {
        val perms = arrayOf(
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.POST_NOTIFICATIONS
        )
        val needed = perms.filter {
            ContextCompat.checkSelfPermission(requireContext(), it) != PackageManager.PERMISSION_GRANTED
        }
        if (needed.isNotEmpty()) {
            ActivityCompat.requestPermissions(requireActivity(), needed.toTypedArray(), PERMISSION_REQUEST)
        }
    }

    private fun startQuickScan() {
        if (isScanning) return
        isScanning = true
        setButtonsEnabled(false)
        progressContainer.visibility = View.VISIBLE
        progressText.text = "Quick scanning downloads..."

        lifecycleScope.launch {
            fileScanner.quickScan().collect { progress ->
                updateProgress(progress)
                if (progress.isComplete) {
                    onScanComplete(progress)
                }
            }
        }
    }

    private fun startFullScan() {
        if (isScanning) return

        // On Android 11+ (API 30+), scanning all external storage requires
        // MANAGE_EXTERNAL_STORAGE, which must be granted via a system settings
        // page — it cannot be requested through the normal runtime dialog.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && !Environment.isExternalStorageManager()) {
            Toast.makeText(
                requireContext(),
                "Full scan needs \"All files access\" permission. Please grant it in Settings, then tap Full Scan again.",
                Toast.LENGTH_LONG
            ).show()
            requestManageExternalStorage()
            return
        }

        // Also make sure legacy READ_EXTERNAL_STORAGE is granted on older APIs
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            val granted = ContextCompat.checkSelfPermission(
                requireContext(),
                Manifest.permission.READ_EXTERNAL_STORAGE
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                ActivityCompat.requestPermissions(
                    requireActivity(),
                    arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE),
                    PERMISSION_REQUEST
                )
                Toast.makeText(
                    requireContext(),
                    "Full scan needs storage permission. Please grant it and tap Full Scan again.",
                    Toast.LENGTH_LONG
                ).show()
                return
            }
        }

        isScanning = true
        setButtonsEnabled(false)
        progressContainer.visibility = View.VISIBLE
        progressText.text = "Full scan in progress..."

        lifecycleScope.launch {
            fileScanner.fullScan().collect { progress ->
                updateProgress(progress)
                if (progress.isComplete) {
                    onScanComplete(progress)
                }
            }
        }
    }

    private fun requestManageExternalStorage() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).apply {
                    data = Uri.parse("package:${requireContext().packageName}")
                }
                startActivityForResult(intent, MANAGE_STORAGE_REQUEST)
            } catch (e: Exception) {
                // Some OEM ROMs don't expose the per-app intent; fall back to
                // the generic "all files access" settings page.
                try {
                    val fallback = Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
                    startActivityForResult(fallback, MANAGE_STORAGE_REQUEST)
                } catch (e2: Exception) {
                    Toast.makeText(
                        requireContext(),
                        "Could not open the All Files Access settings page. Please grant it manually in Settings > Apps.",
                        Toast.LENGTH_LONG
                    ).show()
                }
            }
        }
    }

    private fun updateProgress(progress: FileScanner.ScanProgress) {
        scanProgressBar.max = progress.totalFiles.coerceAtLeast(1)
        scanProgressBar.progress = progress.scannedFiles
        progressDetail.text = "${progress.scannedFiles}/${progress.totalFiles} | Threats: ${progress.threatsFound} | ${progress.currentFile.take(40)}"

        // Show threats in the list as they're discovered
        if (progress.threats.isNotEmpty()) {
            threatsHeader.visibility = View.VISIBLE
            threatsAdapter.update(progress.threats)
        }
    }

    private fun onScanComplete(progress: FileScanner.ScanProgress) {
        isScanning = false
        setButtonsEnabled(true)
        progressContainer.visibility = View.GONE

        // Display final threat list
        if (progress.threatsFound > 0) {
            protectionStatus.text = "Threats Found!"
            protectionStatus.setTextColor(resources.getColor(android.R.color.holo_red_dark, null))
            threatsHeader.visibility = View.VISIBLE
            threatsAdapter.update(progress.threats)
        } else {
            protectionStatus.text = "Protected"
            protectionStatus.setTextColor(resources.getColor(android.R.color.holo_green_dark, null))
        }

        lastScanText.text = "Last scan: ${java.text.SimpleDateFormat("MMM d, HH:mm", java.util.Locale.getDefault()).format(java.util.Date())} — ${progress.threatsFound} threat(s)"

        // Save last scan time
        val prefs = androidx.preference.PreferenceManager.getDefaultSharedPreferences(requireContext())
        prefs.edit()
            .putLong("last_scan_time", System.currentTimeMillis())
            .putInt("last_scan_threats", progress.threatsFound)
            .apply()

        // Quarantine all detected threats on a background thread
        if (progress.threats.isNotEmpty()) {
            lifecycleScope.launch(Dispatchers.IO) {
                var quarantined = 0
                var failed = 0
                for (threat in progress.threats) {
                    if (quarantine.quarantine(threat.file, threat.threatName)) {
                        quarantined++
                    } else {
                        failed++
                    }
                }
                withContext(Dispatchers.Main) {
                    if (quarantined > 0) {
                        Toast.makeText(
                            requireContext(),
                            "$quarantined threat(s) quarantined" +
                                if (failed > 0) ", $failed failed" else "",
                            Toast.LENGTH_LONG
                        ).show()
                    }
                    refreshQuarantine()
                    updateStatus()
                }
            }
        }
    }

    private fun updateStatus() {
        val ruleCount = yaraScanner.getRuleCount()
        val mlCount = mlScanner.getModelCount()
        val mlStatus = if (mlScanner.isLoaded()) "Ready ($mlCount models)" else "Disabled"
        statusDetail.text = "YARA rules: $ruleCount | ML: $mlStatus"

        val prefs = androidx.preference.PreferenceManager.getDefaultSharedPreferences(requireContext())
        val lastScan = prefs.getLong("last_scan_time", 0)
        if (lastScan > 0) {
            val threats = prefs.getInt("last_scan_threats", 0)
            lastScanText.text = "Last scan: ${java.text.SimpleDateFormat("MMM d, HH:mm", java.util.Locale.getDefault()).format(java.util.Date(lastScan))} — $threats threat(s)"
        }

        val qCount = quarantine.getQuarantineCount()
        quarantineCount.text = "$qCount file(s) quarantined"
        quarantineAdapter.update(quarantine.listQuarantine(), quarantine)
    }

    private fun refreshQuarantine() {
        val qCount = quarantine.getQuarantineCount()
        quarantineCount.text = "$qCount file(s) quarantined"
        quarantineAdapter.update(quarantine.listQuarantine(), quarantine)
    }

    private fun setButtonsEnabled(enabled: Boolean) {
        quickScanBtn.isEnabled = enabled
        fullScanBtn.isEnabled = enabled
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        // Permissions may have been granted — update UI
        updateStatus()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == MANAGE_STORAGE_REQUEST) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && Environment.isExternalStorageManager()) {
                Toast.makeText(requireContext(), "Permission granted. Starting full scan...", Toast.LENGTH_SHORT).show()
                startFullScan()
            } else {
                Toast.makeText(
                    requireContext(),
                    "All files access was not granted. Full scan will only cover app-private storage.",
                    Toast.LENGTH_LONG
                ).show()
            }
        }
    }
}
