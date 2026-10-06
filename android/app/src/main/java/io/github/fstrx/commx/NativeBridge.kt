package io.github.fstrx.commx

import android.content.Context

/**
 * The Rust core (crates/commx-android): the commx daemon and voice engine,
 * running in this process. Requests and events are the same JSON lines the
 * desktop TUI uses. Functions returning String? return null on success and
 * an error message otherwise (nextEvent/audioState return data).
 */
object NativeBridge {
    init {
        System.loadLibrary("commx_android")
    }

    @JvmStatic external fun start(context: Context, dataDir: String, listen: String, noUdp: Boolean): String?

    @JvmStatic external fun send(json: String): String?

    /** Next event JSON, or null after [timeoutMs] with nothing to report. */
    @JvmStatic external fun nextEvent(timeoutMs: Long): String?

    @JvmStatic external fun voiceStart(roomId: String, muted: Boolean): String?

    @JvmStatic external fun voiceStop()

    @JvmStatic external fun voiceMute(muted: Boolean)

    /** `{"active":bool,"level":float,"speaking":[names]}` */
    @JvmStatic external fun audioState(): String?

    /** Nukes every room (peers are told) and stops the node. */
    @JvmStatic external fun stop()
}
