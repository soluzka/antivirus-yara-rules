package com.soluzka.antivirus

import android.app.Application
import androidx.preference.PreferenceManager
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit

class AntivirusApp : Application() {

    override fun onCreate() {
        super.onCreate()
        NotificationHelper.createChannel(this)
        scheduleAlertWorker()
    }

    private fun scheduleAlertWorker() {
        val prefs = PreferenceManager.getDefaultSharedPreferences(this)
        val intervalMinutes = prefs.getString("poll_interval", "15")?.toLongOrNull() ?: 15

        val request = PeriodicWorkRequestBuilder<AlertWorker>(intervalMinutes, TimeUnit.MINUTES)
            .build()

        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            "security_alerts",
            ExistingPeriodicWorkPolicy.UPDATE,
            request
        )
    }
}
