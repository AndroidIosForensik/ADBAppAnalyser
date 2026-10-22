package de.rechenhilfe.app

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

data class ChatMessage(
    val peer: String,
    val text: String,
    val outgoing: Boolean,
    val timestamp: Long = System.currentTimeMillis(),
)

/**
 * Lokale Ablage des Nachrichtenverlaufs (SQLite). allowBackup ist im Manifest
 * deaktiviert, damit der Verlauf nicht ins Cloud-Backup gelangt.
 */
class ChatDatabase(context: Context) :
    SQLiteOpenHelper(context, "verlauf.db", null, 1) {

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            "CREATE TABLE messages (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "peer TEXT, text TEXT, outgoing INTEGER, ts INTEGER)"
        )
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        db.execSQL("DROP TABLE IF EXISTS messages")
        onCreate(db)
    }

    fun insert(msg: ChatMessage) {
        writableDatabase.insert(
            "messages", null,
            ContentValues().apply {
                put("peer", msg.peer)
                put("text", msg.text)
                put("outgoing", if (msg.outgoing) 1 else 0)
                put("ts", msg.timestamp)
            }
        )
    }

    fun recent(limit: Int = 200): List<ChatMessage> {
        val out = ArrayList<ChatMessage>()
        readableDatabase.rawQuery(
            "SELECT peer, text, outgoing, ts FROM messages ORDER BY ts ASC LIMIT ?",
            arrayOf(limit.toString())
        ).use { c ->
            while (c.moveToNext()) {
                out.add(
                    ChatMessage(c.getString(0), c.getString(1), c.getInt(2) == 1, c.getLong(3))
                )
            }
        }
        return out
    }
}
