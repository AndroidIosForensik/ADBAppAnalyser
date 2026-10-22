package de.rechenhilfe.app

import android.content.Context
import android.os.Handler
import android.os.Looper
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf

/**
 * Gemeinsamer Zustand fuer Chat-UI und Foreground-Dienst: Verbindung,
 * Nachrichtenliste (fuer Compose beobachtbar) und Verbindungsstatus.
 */
object ChatRepository : RelayConnection.Events {

    val messages = mutableStateListOf<ChatMessage>()
    val connected = mutableStateOf(false)
    val onlinePeers = mutableStateListOf<String>()

    var userName: String = ""
        private set

    /** Wird vom Dienst gesetzt, um bei eingehenden Nachrichten zu benachrichtigen. */
    var onIncoming: ((ChatMessage) -> Unit)? = null

    private val main = Handler(Looper.getMainLooper())
    private var connection: RelayConnection? = null
    private var db: ChatDatabase? = null
    private var appContext: Context? = null
    private var started = false

    fun start(context: Context) {
        if (started) return
        started = true
        appContext = context.applicationContext
        val prefs = context.getSharedPreferences("chat", Context.MODE_PRIVATE)
        userName = prefs.getString("user", null) ?: ("nutzer" + (1000..9999).random())
        prefs.edit().putString("user", userName).apply()

        db = ChatDatabase(context.applicationContext)
        main.post { messages.addAll(db!!.recent()) }

        connection = RelayConnection(context.applicationContext, userName, this).also { it.connect() }
    }

    /** Setzt einen eigenen (merkbaren) Namen und verbindet damit neu. */
    fun setUserName(name: String) {
        val ctx = appContext ?: return
        // Servergueltige Zeichen erzwingen: [A-Za-z0-9_-], max. 32.
        val clean = name.trim().replace(Regex("[^A-Za-z0-9_-]"), "").take(32)
        if (clean.isEmpty() || clean == userName) return
        userName = clean
        ctx.getSharedPreferences("chat", Context.MODE_PRIVATE)
            .edit().putString("user", clean).apply()
        connection?.close()
        connected.value = false
        connection = RelayConnection(ctx, clean, this).also { it.connect() }
    }

    fun send(to: String, text: String) {
        val msg = ChatMessage(peer = to, text = text, outgoing = true)
        db?.insert(msg)
        connection?.sendMessage(to, text)
        main.post { messages.add(msg) }
    }

    fun stop() {
        connection?.close()
        started = false
    }

    // -- RelayConnection.Events ------------------------------------------

    override fun onConnected() {
        main.post { connected.value = true }
    }

    override fun onDisconnected() {
        main.post { connected.value = false }
    }

    override fun onMessage(from: String, id: String, text: String) {
        val msg = ChatMessage(peer = from, text = text, outgoing = false)
        db?.insert(msg)
        main.post {
            messages.add(msg)
            onIncoming?.invoke(msg)
        }
    }

    override fun onPresence(user: String, online: Boolean) {
        main.post {
            if (online) {
                if (!onlinePeers.contains(user)) onlinePeers.add(user)
            } else {
                onlinePeers.remove(user)
            }
        }
    }
}
