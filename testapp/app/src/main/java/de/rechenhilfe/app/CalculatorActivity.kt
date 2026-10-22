package de.rechenhilfe.app

import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Sichtbare Tarnung: ein voll funktionsfaehiger Taschenrechner. Wird der in
 * BuildConfig hinterlegte Entsperr-Code eingegeben und "=" gedrueckt, oeffnet sich
 * der versteckte Chat statt einer Rechnung.
 */
class CalculatorActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Benachrichtigungsrecht (Android 13+) fuer spaetere Chat-Hinweise.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerForActivityResult(ActivityResultContracts.RequestPermission()) {}
                .launch(android.Manifest.permission.POST_NOTIFICATIONS)
        }
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    Calculator(onUnlock = { openChat() })
                }
            }
        }
    }

    private fun openChat() {
        ChatService.start(this)
        startActivity(Intent(this, ChatActivity::class.java))
    }
}

@androidx.compose.runtime.Composable
private fun Calculator(onUnlock: () -> Unit) {
    var display by remember { mutableStateOf("0") }
    var stored by remember { mutableStateOf<Double?>(null) }
    var pendingOp by remember { mutableStateOf<String?>(null) }
    var freshInput by remember { mutableStateOf(true) }

    fun inputDigit(d: String) {
        display = if (freshInput || display == "0") d else display + d
        freshInput = false
    }

    fun setOp(op: String) {
        stored = display.toDoubleOrNull()
        pendingOp = op
        freshInput = true
    }

    fun equals() {
        // Entsperrung: exakt der Code, dann "=" -> Chat oeffnen.
        if (display == ChatConfig.unlockCode) {
            display = "0"; stored = null; pendingOp = null; freshInput = true
            onUnlock()
            return
        }
        val a = stored
        val b = display.toDoubleOrNull()
        val op = pendingOp
        if (a != null && b != null && op != null) {
            val r = when (op) {
                "+" -> a + b
                "-" -> a - b
                "×" -> a * b
                "÷" -> if (b != 0.0) a / b else Double.NaN
                else -> b
            }
            display = if (r % 1.0 == 0.0) r.toLong().toString() else r.toString()
            stored = null; pendingOp = null; freshInput = true
        }
    }

    fun clear() {
        display = "0"; stored = null; pendingOp = null; freshInput = true
    }

    val rows = listOf(
        listOf("C", "÷", "×", "-"),
        listOf("7", "8", "9", "+"),
        listOf("4", "5", "6", "="),
        listOf("1", "2", "3", "0"),
    )

    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .navigationBarsPadding()
            .padding(16.dp)
    ) {
        Box(
            modifier = Modifier.fillMaxWidth().weight(1f),
            contentAlignment = Alignment.BottomEnd
        ) {
            Text(text = display, fontSize = 56.sp, textAlign = TextAlign.End, maxLines = 1)
        }
        rows.forEach { row ->
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                row.forEach { key ->
                    Button(
                        onClick = {
                            when (key) {
                                "C" -> clear()
                                "=" -> equals()
                                "+", "-", "×", "÷" -> setOp(key)
                                else -> inputDigit(key)
                            }
                        },
                        modifier = Modifier.weight(1f).padding(vertical = 6.dp)
                    ) { Text(key, fontSize = 22.sp) }
                }
            }
        }
    }
}
