package de.rechenhilfe.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat

/**
 * Haelt die Relay-Verbindung als Foreground-Dienst dauerhaft offen und meldet
 * eingehende Nachrichten - bewusst mit neutraler Benachrichtigung ohne Inhalt.
 *
 * Foreground-Service-Typ ist remoteMessaging (siehe Manifest); genau dieser Typ
 * ist ein starkes Signal fuer eine dauerhafte Nachrichtenverbindung.
 */
class ChatService : Service() {

    override fun onCreate() {
        super.onCreate()
        createChannels()
        startAsForeground()
        ChatRepository.start(this)
        ChatRepository.onIncoming = { notifyIncoming() }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY

    override fun onBind(intent: Intent?): IBinder? = null

    private fun startAsForeground() {
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, CalculatorActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ONGOING)
            .setContentTitle("Rechner")
            .setContentText("Aktiv")
            .setSmallIcon(R.drawable.ic_stat)
            .setContentIntent(open)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceCompat.startForeground(
                this, ONGOING_ID, notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING
            )
        } else {
            startForeground(ONGOING_ID, notification)
        }
    }

    private fun notifyIncoming() {
        val open = PendingIntent.getActivity(
            this, 1, Intent(this, ChatActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        val notification = NotificationCompat.Builder(this, CHANNEL_MESSAGES)
            .setContentTitle("Neue Nachricht")
            .setSmallIcon(R.drawable.ic_stat)
            .setContentIntent(open)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .build()
        val mgr = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        mgr.notify(MESSAGE_ID, notification)
    }

    private fun createChannels() {
        val mgr = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        mgr.createNotificationChannel(
            NotificationChannel(CHANNEL_ONGOING, "Dienst", NotificationManager.IMPORTANCE_MIN)
        )
        mgr.createNotificationChannel(
            NotificationChannel(CHANNEL_MESSAGES, "Hinweise", NotificationManager.IMPORTANCE_DEFAULT)
        )
    }

    companion object {
        private const val CHANNEL_ONGOING = "dienst"
        private const val CHANNEL_MESSAGES = "hinweise"
        private const val ONGOING_ID = 1
        private const val MESSAGE_ID = 2

        fun start(context: Context) {
            val intent = Intent(context, ChatService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }
    }
}
