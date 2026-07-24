package com.aether.webapp

import android.os.Bundle
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.viewinterop.AndroidView
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import kotlinx.coroutines.delay
import java.io.File

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!Python.isStarted()) { Python.start(AndroidPlatform(this)) }

        val aetherFile = File(filesDir, "aether")
        if (!aetherFile.exists()) {
            try { assets.open("aether").use { input -> aetherFile.outputStream().use { output -> input.copyTo(output) } }; aetherFile.setExecutable(true, true) } catch (e: Exception) {}
        }

        Thread {
            try {
                val py = Python.getInstance()
                val module = py.getModule("server")
                module.callAttr("main", aetherFile.absolutePath)
            } catch (e: Exception) { e.printStackTrace() }
        }.start()

        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    var isServerReady by remember { mutableStateOf(false) }
                    LaunchedEffect(Unit) { delay(3000); isServerReady = true }
                    if (isServerReady) { WebViewScreen() } else { CircularProgressIndicator(modifier = Modifier.fillMaxSize()) }
                }
            }
        }
    }
}

@Composable
fun WebViewScreen() {
    AndroidView(
        factory = { context ->
            WebView(context).apply {
                settings.javaScriptEnabled = true; settings.domStorageEnabled = true; webViewClient = WebViewClient()
                loadUrl("http://127.0.0.1:1819")
            }
        },
        modifier = Modifier.fillMaxSize()
    )
}
