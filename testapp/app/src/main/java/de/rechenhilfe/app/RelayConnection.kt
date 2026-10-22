package de.rechenhilfe.app

import android.content.Context
import android.util.Log
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.UUID
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * WebSocket-Verbindung zum Relay-Server.
 *
 * Sicherheit wie in vielen selbst gebauten Chat-Apps: TLS zu einer festen
 * wss://IP:Port, wobei das selbstsignierte Serverzertifikat aus [R.raw.relay_cert]
 * als alleiniger Trust-Anchor dient und zusaetzlich per SPKI-Pin
 * (OkHttp [CertificatePinner]) festgenagelt wird. Automatischer Reconnect.
 */
class RelayConnection(
    private val context: Context,
    private val user: String,
    private val listener: Events,
) : WebSocketListener() {

    interface Events {
        fun onConnected()
        fun onDisconnected()
        fun onMessage(from: String, id: String, text: String)
        fun onPresence(user: String, online: Boolean)
    }

    private val client: OkHttpClient = buildClient(context)
    private var webSocket: WebSocket? = null
    @Volatile private var closed = false

    fun connect() {
        closed = false
        open()
    }

    private fun open() {
        val url = httpUrl(ChatConfig.serverUrl)
        Log.i(TAG, "verbinde zu $url (user=$user, pinGesetzt=${ChatConfig.pin.startsWith("sha256/")})")
        val request = Request.Builder().url(url).build()
        webSocket = client.newWebSocket(request, this)
    }

    fun sendMessage(to: String, text: String): String {
        val id = UUID.randomUUID().toString()
        val payload = JSONObject()
            .put("type", "msg").put("to", to).put("id", id).put("text", text)
        val ok = webSocket?.send(payload.toString()) ?: false
        Log.i(TAG, "sende an '$to' (id=$id) -> angenommen=$ok, socket=${webSocket != null}")
        return id
    }

    fun close() {
        closed = true
        webSocket?.close(1000, null)
    }

    // -- WebSocketListener ------------------------------------------------

    override fun onOpen(webSocket: WebSocket, response: Response) {
        Log.i(TAG, "onOpen (HTTP ${response.code}) - sende hello")
        val hello = JSONObject()
            .put("type", "hello").put("user", user).put("token", ChatConfig.token)
        webSocket.send(hello.toString())
    }

    override fun onMessage(webSocket: WebSocket, text: String) {
        val msg = runCatching { JSONObject(text) }.getOrNull() ?: return
        Log.i(TAG, "onMessage type=${msg.optString("type")}")
        when (msg.optString("type")) {
            "hello_ok" -> listener.onConnected()
            "msg" -> listener.onMessage(
                msg.optString("from"), msg.optString("id"), msg.optString("text")
            )
            "presence" -> listener.onPresence(
                msg.optString("user"), msg.optBoolean("online")
            )
        }
    }

    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
        Log.e(TAG, "onFailure (HTTP ${response?.code}): ${t.javaClass.simpleName}: ${t.message}", t)
        listener.onDisconnected()
        scheduleReconnect()
    }

    override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
        Log.i(TAG, "onClosed code=$code reason=$reason")
        listener.onDisconnected()
        if (!closed) scheduleReconnect()
    }

    private fun scheduleReconnect() {
        if (closed) return
        Thread {
            try {
                Thread.sleep(3000)
            } catch (_: InterruptedException) {
            }
            if (!closed) open()
        }.start()
    }

    private fun buildClient(context: Context): OkHttpClient {
        val trustManager = embeddedTrustManager(context)
        val sslContext = SSLContext.getInstance("TLS").apply {
            init(null, arrayOf(trustManager), null)
        }
        val builder = OkHttpClient.Builder()
            .sslSocketFactory(sslContext.socketFactory, trustManager)
            .pingInterval(20, java.util.concurrent.TimeUnit.SECONDS)
        // Zusaetzliches SPKI-Pinning, falls in der Konfiguration gesetzt.
        if (ChatConfig.pin.startsWith("sha256/")) {
            builder.certificatePinner(
                CertificatePinner.Builder().add(host(ChatConfig.serverUrl), ChatConfig.pin).build()
            )
        }
        return builder.build()
    }

    /** TrustManager, der ausschliesslich dem eingebetteten Relay-Zertifikat vertraut. */
    private fun embeddedTrustManager(context: Context): X509TrustManager {
        val cf = CertificateFactory.getInstance("X.509")
        val ca: X509Certificate = context.resources.openRawResource(R.raw.relay_cert).use {
            cf.generateCertificate(it) as X509Certificate
        }
        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setCertificateEntry("relay", ca)
        }
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(keyStore)
        return tmf.trustManagers[0] as X509TrustManager
    }

    private fun httpUrl(wsUrl: String): String =
        wsUrl.replaceFirst("wss://", "https://").replaceFirst("ws://", "http://")

    private fun host(wsUrl: String): String =
        wsUrl.substringAfter("://").substringBefore(":").substringBefore("/")

    companion object {
        private const val TAG = "RelayConn"
    }
}
