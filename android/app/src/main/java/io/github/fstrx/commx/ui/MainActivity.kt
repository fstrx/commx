package io.github.fstrx.commx.ui

import android.Manifest
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import io.github.fstrx.commx.CommxService

class MainActivity : ComponentActivity() {
    private var onMicResult: ((Boolean) -> Unit)? = null
    private val micPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        onMicResult?.invoke(granted)
        onMicResult = null
    }
    private val notifPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No screenshots, no screen recording, no thumbnail in Recents.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= 33) notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        CommxService.start(this)
        setContent {
            CommxApp(
                requestMic = { cb ->
                    onMicResult = cb
                    micPermission.launch(Manifest.permission.RECORD_AUDIO)
                },
                copySecret = ::copySecret,
                pasteText = ::pasteText,
                quit = {
                    CommxService.quit(this)
                    finishAndRemoveTask()
                },
            )
        }
    }

    /** Copy without showing a preview/keyboard suggestion (Android 13+ sensitive flag). */
    private fun copySecret(label: String, text: String) {
        val clip = ClipData.newPlainText(label, text)
        if (Build.VERSION.SDK_INT >= 33) {
            clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
        }
        (getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(clip)
    }

    private fun pasteText(): String? {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        return cm.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(this)?.toString()
    }
}
