package com.soluzka.antivirus

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat

object NotificationHelper {

    private const val CHANNEL_ID = "security_alerts"
    private const val NOTIFICATION_ID_BASE = 1000

    fun createChannel(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val name = context.getString(R.string.channel_name)
            val desc = context.getString(R.string.channel_description)
            val channel = NotificationChannel(CHANNEL_ID, name, NotificationManager.IMPORTANCE_HIGH).apply {
                description = desc
                enableVibration(true)
            }
            val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    fun showNotification(context: Context, title: String, message: String) {
        createChannel(context)

        val builder = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(title)
            .setContentText(message)
            .setStyle(NotificationCompat.BigTextStyle().bigText(message))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)

        try {
            NotificationManagerCompat.from(context).notify(
                NOTIFICATION_ID_BASE + System.currentTimeMillis().toInt() % 1000,
                builder.build()
            )
        } catch (e: SecurityException) {
            // POST_NOTIFICATIONS permission not granted — ignore
        }
    }
}
