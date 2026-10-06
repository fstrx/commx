package io.github.fstrx.commx

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import io.github.fstrx.commx.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import java.io.File

/**
 * Runs the commx node for as long as the app wants it, screen on or off.
 *
 * A node that drops destroys its rooms (that's the kill switch), so while
 * any room is open this holds a partial wake lock and a Wi-Fi lock — the
 * Android equivalent of the desktop daemon's caffeinate/systemd-inhibit.
 * If Android kills the process anyway, peers see the drop and nuke.
 */
class CommxService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    @Volatile private var running = false
    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null
    private var micInForeground = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
        goForeground(withMic = false, rooms = 0)

        val dir = File(filesDir, "commx").apply { mkdirs() }
        val err = NativeBridge.start(applicationContext, dir.absolutePath, "0.0.0.0:4700", false)
        if (err != null) {
            Commx.notify("couldn't start node: $err", true)
            stopSelf()
            return
        }
        running = true
        Commx.markStarted()
        Commx.onVoiceChange = ::onVoiceChange

        // Event pump: daemon → app state.
        Thread({
            while (running) {
                NativeBridge.nextEvent(500)?.let(Commx::onEvent)
            }
        }, "commx-events").start()
        Commx.request("status")
        Commx.request("alias_list")

        // Status refresh (network label, link quality).
        scope.launch {
            while (running) {
                kotlinx.coroutines.delay(3000)
                Commx.request("status")
            }
        }
        // Stay awake (and keep the notification honest) while rooms are open.
        scope.launch {
            Commx.state.map { it.rooms.size }.distinctUntilChanged().collect { n ->
                holdAwake(n > 0)
                goForeground(withMic = micInForeground, rooms = n)
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_QUIT) {
            stopSelf()
            return START_NOT_STICKY
        }
        // Not sticky: a node restarted behind the user's back would be a
        // fresh node with no rooms anyway.
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        running = false
        Commx.onVoiceChange = null
        NativeBridge.voiceStop()
        NativeBridge.stop() // nukes every room, tells peers
        holdAwake(false)
        scope.cancel()
        super.onDestroy()
    }

    private fun onVoiceChange(callRoom: String?) {
        if (callRoom == null) {
            NativeBridge.voiceStop()
            Commx.audioMeters(false)
            micInForeground = false
            goForeground(withMic = false, rooms = Commx.state.value.rooms.size)
            return
        }
        val granted = ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED
        if (!granted) {
            Commx.notify("microphone permission needed for calls", true)
            Commx.request("hangup", "room_id" to callRoom)
            return
        }
        micInForeground = true
        goForeground(withMic = true, rooms = Commx.state.value.rooms.size)
        val err = NativeBridge.voiceStart(callRoom, !Commx.state.value.micOpen)
        if (err != null) {
            Commx.notify("audio: $err", true)
            Commx.request("hangup", "room_id" to callRoom)
            return
        }
        Commx.audioMeters(true)
    }

    private fun holdAwake(on: Boolean) {
        if (on) {
            if (wakeLock?.isHeld != true) {
                wakeLock = (getSystemService(Context.POWER_SERVICE) as PowerManager)
                    .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "commx:rooms")
                    .apply { setReferenceCounted(false); acquire() }
            }
            if (wifiLock?.isHeld != true) {
                @Suppress("DEPRECATION")
                val mode = if (Build.VERSION.SDK_INT >= 29) WifiManager.WIFI_MODE_FULL_LOW_LATENCY else WifiManager.WIFI_MODE_FULL_HIGH_PERF
                wifiLock = (applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager)
                    .createWifiLock(mode, "commx:rooms")
                    .apply { setReferenceCounted(false); acquire() }
            }
        } else {
            wakeLock?.takeIf { it.isHeld }?.release()
            wifiLock?.takeIf { it.isHeld }?.release()
        }
    }

    private fun createChannel() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL, "commx node", NotificationManager.IMPORTANCE_LOW).apply {
                description = "Shown while your node is running"
                lockscreenVisibility = Notification.VISIBILITY_SECRET
                setShowBadge(false)
            }
        )
    }

    private fun goForeground(withMic: Boolean, rooms: Int) {
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val quit = PendingIntent.getService(
            this, 1, Intent(this, CommxService::class.java).setAction(ACTION_QUIT), PendingIntent.FLAG_IMMUTABLE,
        )
        // No room names or message content in the notification, ever.
        val text = when {
            withMic -> "in a call"
            rooms == 0 -> "no rooms open"
            else -> "$rooms room${if (rooms == 1) "" else "s"} open · stays awake"
        }
        val n = NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("commx")
            .setContentText(text)
            .setOngoing(true)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setContentIntent(open)
            .addAction(0, "Quit & nuke all", quit)
            .build()
        // The microphone type is what lets a call keep working with the screen off.
        val mic = if (withMic && Build.VERSION.SDK_INT >= 30) ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE else 0
        val types = if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE or mic else mic
        ServiceCompat.startForeground(this, NOTIFICATION_ID, n, types)
    }

    companion object {
        const val ACTION_QUIT = "io.github.fstrx.commx.QUIT"
        private const val CHANNEL = "node"
        private const val NOTIFICATION_ID = 1

        fun start(ctx: Context) = ContextCompat.startForegroundService(ctx, Intent(ctx, CommxService::class.java))

        fun quit(ctx: Context) = ctx.stopService(Intent(ctx, CommxService::class.java))
    }
}
