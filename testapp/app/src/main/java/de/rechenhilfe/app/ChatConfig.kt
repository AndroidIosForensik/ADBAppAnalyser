package de.rechenhilfe.app

/**
 * Konfiguration aus BuildConfig (gespeist aus app/chat.properties beim Build).
 * So liegen Serveradresse, Pin, Token und der Entsperr-Code nicht im Klartext im
 * Quellcode-Repository.
 */
object ChatConfig {
    val serverUrl: String get() = BuildConfig.SERVER_URL
    val pin: String get() = BuildConfig.RELAY_PIN
    val token: String get() = BuildConfig.RELAY_TOKEN
    val unlockCode: String get() = BuildConfig.UNLOCK_CODE
}
