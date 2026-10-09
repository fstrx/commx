package io.github.fstrx.commx

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject

data class RoomUi(
    val id: String,
    val name: String,
    val anyMember: Boolean,
    val grace: Long,
    val isDm: Boolean,
    val isHost: Boolean,
    val alias: String,
    val hostFp: String,
    val members: List<String>,
    val link: String,
)

data class Line(val from: String, val text: String, val tsMin: Long, val mine: Boolean, val system: Boolean, val local: Boolean = false)

data class CallUi(val participants: List<String>, val joined: Boolean)

data class FileUi(val no: Int, val name: String, val size: Long, val from: String, val state: String)

data class AliasUi(val name: String, val fingerprint: String, val ephemeral: Boolean, val active: Boolean)

data class Notice(val text: String, val error: Boolean)

data class AppState(
    val started: Boolean = false,
    val alias: String? = null,
    val fingerprint: String? = null,
    val network: String = "",
    val rooms: List<RoomUi> = emptyList(),
    val lines: Map<String, List<Line>> = emptyMap(),
    val home: List<Notice> = emptyList(),
    val aliases: List<AliasUi> = emptyList(),
    val calls: Map<String, CallUi> = emptyMap(),
    val files: Map<String, List<FileUi>> = emptyMap(),
    val unread: Set<String> = emptySet(),
    val selected: String? = null,
    val notice: Notice? = null,
    /** Latest invite per room (shown in a dialog, copied on request). */
    val invites: Map<String, String> = emptyMap(),
    val muted: Boolean = false,
    val talking: Boolean = false,
    val ptt: Boolean = false,
    val micLevel: Float = 0f,
    val speaking: List<String> = emptyList(),
) {
    val current: RoomUi? get() = rooms.firstOrNull { it.id == selected }
    val callRoom: String? get() = calls.entries.firstOrNull { it.value.joined }?.key
    val micOpen: Boolean get() = !muted && (!ptt || talking)
}

private const val MAX_LINES = 500

/**
 * App-wide state, fed by daemon events. Mirrors the TUI's App: it only knows
 * what the daemon tells it, and forgets a room the moment it's nuked.
 *
 * Unlike the Rust side, JVM strings can't be wiped; message text here lives
 * until garbage-collected. Rooms are dropped from state on nuke.
 */
object Commx {
    private val _state = MutableStateFlow(AppState())
    val state: StateFlow<AppState> = _state

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var audioJob: Job? = null

    /** Called by the service when audio needs (re)configuring. */
    @Volatile var onVoiceChange: ((roomId: String?) -> Unit)? = null

    fun markStarted() = _state.update { it.copy(started = true) }

    fun request(req: JSONObject) {
        NativeBridge.send(req.toString())?.let { notify(it, true) }
    }

    fun request(op: String, vararg kv: Pair<String, Any?>) {
        val o = JSONObject().put("op", op)
        for ((k, v) in kv) o.put(k, v ?: JSONObject.NULL)
        request(o)
    }

    fun notify(text: String, error: Boolean) = _state.update {
        it.copy(notice = Notice(text, error), home = (it.home + Notice(text, error)).takeLast(300))
    }

    fun select(roomId: String?) = _state.update {
        it.copy(selected = roomId, unread = if (roomId == null) it.unread else it.unread - roomId)
    }

    fun setMuted(m: Boolean) {
        _state.update { it.copy(muted = m) }
        NativeBridge.voiceMute(!_state.value.micOpen)
    }

    fun setPtt(on: Boolean) {
        _state.update { it.copy(ptt = on, talking = false) }
        NativeBridge.voiceMute(!_state.value.micOpen)
    }

    fun setTalking(t: Boolean) {
        _state.update { it.copy(talking = t) }
        NativeBridge.voiceMute(!_state.value.micOpen)
    }

    fun clearNotice() = _state.update { it.copy(notice = null) }

    private fun localLine(roomId: String, text: String) = _state.update {
        val l = Line("~", text, System.currentTimeMillis() / 60000, mine = false, system = true, local = true)
        it.copy(lines = it.lines + (roomId to ((it.lines[roomId] ?: emptyList()) + l).takeLast(MAX_LINES)))
    }

    private fun parseRoom(o: JSONObject) = RoomUi(
        id = o.getString("room_id"),
        name = o.optString("name"),
        anyMember = o.optString("kill_mode") == "AnyMember",
        grace = o.optLong("grace_secs"),
        isDm = o.optBoolean("is_dm"),
        isHost = o.optBoolean("is_host"),
        alias = o.optString("alias"),
        hostFp = o.optString("host_fp"),
        members = o.optJSONArray("members").strings(),
        link = o.optString("link"),
    )

    private fun parseLine(o: JSONObject) = Line(
        from = o.optString("from"),
        text = o.optString("text"),
        tsMin = o.optLong("ts_min"),
        mine = o.optBoolean("mine"),
        system = o.optBoolean("system"),
    )

    private fun JSONArray?.strings(): List<String> =
        if (this == null) emptyList() else (0 until length()).map { getString(it) }

    private fun upsert(rooms: List<RoomUi>, r: RoomUi): Pair<List<RoomUi>, Boolean> {
        val i = rooms.indexOfFirst { it.id == r.id }
        return if (i >= 0) rooms.toMutableList().also { it[i] = r } to false else (rooms + r) to true
    }

    /** One daemon event (a JSON line). Runs on the service's event thread. */
    fun onEvent(json: String) {
        val ev = try {
            JSONObject(json)
        } catch (_: Exception) {
            return
        }
        when (ev.optString("ev")) {
            "ok" -> notify(ev.optString("msg"), false)
            "error" -> notify(ev.optString("msg"), true)
            "status" -> {
                val rooms = (0 until (ev.optJSONArray("rooms")?.length() ?: 0)).map { parseRoom(ev.getJSONArray("rooms").getJSONObject(it)) }
                val fresh = mutableListOf<String>()
                _state.update { s ->
                    var list = s.rooms
                    for (r in rooms) {
                        val (l, new) = upsert(list, r)
                        list = l
                        if (new) fresh += r.id
                    }
                    s.copy(
                        alias = if (ev.isNull("alias")) null else ev.optString("alias"),
                        fingerprint = if (ev.isNull("fingerprint")) null else ev.optString("fingerprint"),
                        network = ev.optString("listen"),
                        rooms = list,
                        // A status refresh can see a just-joined room before its
                        // "room" event; open it either way.
                        selected = s.selected ?: fresh.lastOrNull(),
                    )
                }
                fresh.forEach { request("history", "room_id" to it) }
            }
            "aliases" -> {
                val a = ev.optJSONArray("list")
                val list = (0 until (a?.length() ?: 0)).map {
                    val o = a!!.getJSONObject(it)
                    AliasUi(o.optString("name"), o.optString("fingerprint"), o.optBoolean("ephemeral"), o.optBoolean("active"))
                }
                _state.update { it.copy(aliases = list) }
            }
            "invite_code" -> {
                val id = ev.getString("room_id")
                val code = ev.getString("code")
                _state.update { it.copy(invites = it.invites + (id to code)) }
                localLine(
                    id,
                    if (ev.optBoolean("reusable")) "reusable password invite — tap Invite to copy it; send the password separately"
                    else "invite (single use, 10 min) — tap Invite to copy it",
                )
            }
            "room" -> {
                val r = parseRoom(ev.getJSONObject("room"))
                var isNew = false
                _state.update { s ->
                    val (l, new) = upsert(s.rooms, r)
                    isNew = new
                    s.copy(rooms = l, selected = if (new || s.selected == null) r.id else s.selected)
                }
                if (isNew) request("history", "room_id" to r.id)
            }
            "line" -> {
                val id = ev.getString("room_id")
                val line = parseLine(ev.getJSONObject("line"))
                _state.update { s ->
                    s.copy(
                        lines = s.lines + (id to ((s.lines[id] ?: emptyList()) + line).takeLast(MAX_LINES)),
                        unread = if (s.selected == id) s.unread else s.unread + id,
                    )
                }
            }
            "history" -> {
                val id = ev.getString("room_id")
                val arr = ev.optJSONArray("lines")
                val hist = (0 until (arr?.length() ?: 0)).map { parseLine(arr!!.getJSONObject(it)) }
                _state.update { s ->
                    val local = (s.lines[id] ?: emptyList()).filter { it.local }
                    s.copy(lines = s.lines + (id to (hist + local).takeLast(MAX_LINES)))
                }
            }
            "files" -> {
                val id = ev.getString("room_id")
                val arr = ev.optJSONArray("list")
                val list = (0 until (arr?.length() ?: 0)).map {
                    val o = arr!!.getJSONObject(it)
                    FileUi(o.optInt("no"), o.optString("name"), o.optLong("size"), o.optString("from"), o.optString("state"))
                }
                _state.update { it.copy(files = it.files + (id to list)) }
            }
            "call" -> {
                val id = ev.getString("room_id")
                val c = ev.optJSONObject("call")
                _state.update { s ->
                    if (c == null) s.copy(calls = s.calls - id)
                    else s.copy(calls = s.calls + (id to CallUi(c.optJSONArray("participants").strings(), c.optBoolean("joined"))))
                }
                onVoiceChange?.invoke(_state.value.callRoom)
            }
            "nuked" -> {
                val id = ev.getString("room_id")
                _state.update { s ->
                    s.copy(
                        rooms = s.rooms.filter { it.id != id },
                        lines = s.lines - id,
                        calls = s.calls - id,
                        files = s.files - id,
                        invites = s.invites - id,
                        unread = s.unread - id,
                        selected = if (s.selected == id) null else s.selected,
                    )
                }
                notify("☢ #${ev.optString("name")} nuked — ${ev.optString("reason")}", true)
                onVoiceChange?.invoke(_state.value.callRoom)
            }
        }
    }

    /** Poll the voice engine's meters while a call is up. */
    fun audioMeters(active: Boolean) {
        audioJob?.cancel()
        if (!active) {
            _state.update { it.copy(micLevel = 0f, speaking = emptyList()) }
            return
        }
        audioJob = scope.launch {
            while (isActive) {
                NativeBridge.audioState()?.let { js ->
                    val o = JSONObject(js)
                    _state.update {
                        it.copy(micLevel = o.optDouble("level", 0.0).toFloat(), speaking = o.optJSONArray("speaking").strings())
                    }
                }
                delay(150)
            }
        }
    }
}
