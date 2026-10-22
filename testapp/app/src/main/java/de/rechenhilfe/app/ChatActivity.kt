package de.rechenhilfe.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp

/** Versteckter Chat: kein Launcher-Eintrag, aus der App-Uebersicht ausgeblendet. */
class ChatActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ChatService.start(this)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) { ChatScreen() }
            }
        }
    }
}

@Composable
private fun ChatScreen() {
    var peer by remember { mutableStateOf("") }
    var draft by remember { mutableStateOf("") }
    var myName by remember { mutableStateOf(ChatRepository.userName) }
    val messages = ChatRepository.messages
    val connected by ChatRepository.connected

    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .navigationBarsPadding()
            .imePadding()
            .padding(12.dp)
    ) {
        Text(
            text = if (connected) "Verbunden" else "Verbinde …",
            modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp)
        )
        // Eigener, merkbarer Name (statt Zufallsname), damit der andere dich
        // adressieren kann. "Setzen" verbindet mit dem neuen Namen neu.
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            OutlinedTextField(
                value = myName,
                onValueChange = { myName = it },
                label = { Text("Mein Name") },
                modifier = Modifier.weight(1f)
            )
            Button(onClick = { ChatRepository.setUserName(myName) }) { Text("Setzen") }
        }
        OutlinedTextField(
            value = peer,
            onValueChange = { peer = it },
            label = { Text("An wen? (Name des anderen)") },
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
        )
        LazyColumn(modifier = Modifier.fillMaxWidth().weight(1f).padding(vertical = 8.dp)) {
            items(messages) { m ->
                Text(
                    text = (if (m.outgoing) "→ " else "← ") + m.peer + ": " + m.text,
                    modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
                    textAlign = if (m.outgoing) TextAlign.End else TextAlign.Start
                )
            }
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            OutlinedTextField(
                value = draft,
                onValueChange = { draft = it },
                label = { Text("Nachricht") },
                modifier = Modifier.weight(1f)
            )
            Button(
                onClick = {
                    if (peer.isNotBlank() && draft.isNotBlank()) {
                        ChatRepository.send(peer.trim(), draft.trim())
                        draft = ""
                    }
                }
            ) { Text("Senden") }
        }
    }
}
