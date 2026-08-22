package com.soluzka.antivirus

import android.content.Context
import androidx.preference.PreferenceManager
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * Periodically polls the cloud server for security alerts and shows
 * a native notification when new threats are detected.
 */
class AlertWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val prefs = PreferenceManager.getDefaultSharedPreferences(applicationContext)
        val notificationsEnabled = prefs.getBoolean("notifications_enabled", true)
        if (!notificationsEnabled) return Result.success()

        val serverUrl = prefs.getString("server_url", "") ?: ""
        if (serverUrl.isBlank()) return Result.success()

        val licenseKey = prefs.getString("license_key", "") ?: ""

        return try {
            val alerts = fetchAlerts(serverUrl, licenseKey)
            for (alert in alerts) {
                NotificationHelper.showNotification(
                    applicationContext,
                    alert.optString("title", "Security Alert"),
                    alert.optString("message", "")
                )
            }
            Result.success()
        } catch (e: Exception) {
            Result.retry()
        }
    }

    private fun fetchAlerts(serverUrl: String, licenseKey: String): List<JSONObject> {
        val url = URL("$serverUrl/api/alerts?since=${System.currentTimeMillis() - 3600000}")
        val conn = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 10000
            readTimeout = 10000
            setRequestProperty("Accept", "application/json")
            if (licenseKey.isNotEmpty()) {
                setRequestProperty("X-License-Key", licenseKey)
            }
        }

        try {
            if (conn.responseCode != 200) return emptyList()
            val body = conn.inputStream.bufferedReader().use { it.readText() }
            val json = JSONObject(body)
            val alertsArray = json.optJSONArray("alerts") ?: return emptyList()
            return (0 until alertsArray.length()).map { alertsArray.getJSONObject(it) }
        } finally {
            conn.disconnect()
        }
    }
}
