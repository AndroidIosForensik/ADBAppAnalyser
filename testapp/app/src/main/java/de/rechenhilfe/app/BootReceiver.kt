package de.rechenhilfe.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Startet den Chat-Dienst nach einem Geraeteneustart erneut, damit die
 * Verbindung ohne manuelles Oeffnen der App wiederhergestellt wird.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            ChatService.start(context)
        }
    }
}
