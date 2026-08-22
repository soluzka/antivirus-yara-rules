package com.soluzka.antivirus

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.preference.PreferenceManager

/**
 * Starts the MainActivity when the device finishes booting.
 * This is the Android equivalent of "Startup at Login" — the app
 * launches automatically so the user sees their dashboard without
 * having to tap the icon.
 *
 * Respects the "startup_at_boot" preference — if the user disabled
 * it in Settings, the app will not auto-start.
 *
 * Requires RECEIVE_BOOT_COMPLETED permission (declared in the manifest).
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED &&
            intent.action != "android.intent.action.QUICKBOOT_POWERON" &&
            intent.action != "com.htc.intent.action.QUICKBOOT_POWERON"
        ) {
            return
        }

        // Check if the user has enabled startup at boot
        val prefs = PreferenceManager.getDefaultSharedPreferences(context)
        if (!prefs.getBoolean("startup_at_boot", true)) {
            return
        }

        val launchIntent = Intent(context, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        context.startActivity(launchIntent)
    }
}
