package io.github.fstrx.commx.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.gestures.waitForUpOrCancellation
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Slider
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.isShiftPressed
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.fstrx.commx.AppState
import io.github.fstrx.commx.Cmd
import io.github.fstrx.commx.Commx
import io.github.fstrx.commx.HELP
import io.github.fstrx.commx.Line
import io.github.fstrx.commx.RoomUi
import io.github.fstrx.commx.parseCmd
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

private val Accent = Color(0xFF78DCA0)
private val Danger = Color(0xFFFF5F5F)
private val Dim = Color(0xFF8A938F)
private val Bg = Color(0xFF101614)
private val Panel = Color(0xFF17201D)
private val NameColors = listOf(
    Color(0xFF82AAFF), Color(0xFFFFB464), Color(0xFFC88CFF), Color(0xFFFF82B4), Color(0xFF78D2E6), Color(0xFFE6DC6E),
)

private fun nameColor(n: String) = NameColors[Math.floorMod(n.hashCode(), NameColors.size)]
private val hhmm = DateTimeFormatter.ofPattern("HH:mm").withZone(ZoneId.systemDefault())
private fun time(tsMin: Long) = hhmm.format(Instant.ofEpochSecond(tsMin * 60))

private sealed interface Dialog {
    data object NewRoom : Dialog
    data object Join : Dialog
    data class Invite(val code: String) : Dialog
    data class InvitePassword(val roomId: String) : Dialog
    data class JoinPassword(val code: String) : Dialog
    data class ConfirmNuke(val roomId: String?, val label: String) : Dialog
    data class Passphrase(val newAlias: String?) : Dialog
}

@Composable
fun CommxApp(
    requestMic: ((Boolean) -> Unit) -> Unit,
    copySecret: (String, String) -> Unit,
    pasteText: () -> String?,
    quit: () -> Unit,
) {
    val s by Commx.state.collectAsStateWithLifecycle()
    var dialog by remember { mutableStateOf<Dialog?>(null) }

    fun startCall(roomId: String) = requestMic { ok ->
        if (ok) Commx.request("call", "room_id" to roomId) else Commx.notify("microphone permission denied", true)
    }

    fun run(cmd: Cmd) {
        val room = s.selected
        fun needRoom() = Commx.notify("open a room first", true)
        when (cmd) {
            is Cmd.Say -> if (room == null) needRoom() else if (cmd.text.isNotBlank()) Commx.request("send", "room_id" to room, "text" to cmd.text)
            is Cmd.AliasNew -> if (cmd.ephemeral) Commx.request("alias_new", "name" to cmd.name, "ephemeral" to true, "passphrase" to null)
            else dialog = Dialog.Passphrase(cmd.name)
            is Cmd.AliasUse -> Commx.request("alias_use", "name" to cmd.name)
            Cmd.AliasList -> { Commx.request("alias_list"); Commx.select(null) }
            Cmd.Unlock -> dialog = Dialog.Passphrase(null)
            is Cmd.RoomNew -> Commx.request("room_new", "name" to cmd.name, "kill_mode" to if (cmd.anyMember) "AnyMember" else "HostOnly", "grace_secs" to cmd.grace, "dm" to false)
            is Cmd.Dm -> Commx.request("room_new", "name" to cmd.label, "kill_mode" to "AnyMember", "grace_secs" to 15, "dm" to true)
            Cmd.Invite -> if (room == null) needRoom() else Commx.request("invite", "room_id" to room)
            Cmd.InvitePassword -> if (room == null) needRoom() else dialog = Dialog.InvitePassword(room)
            Cmd.InviteRevoke -> if (room == null) needRoom() else Commx.request("invite_revoke", "room_id" to room)
            is Cmd.Join -> if (cmd.code.startsWith("cx2:")) dialog = Dialog.JoinPassword(cmd.code)
            else Commx.request("join", "code" to cmd.code, "password" to null)
            is Cmd.Nuke -> if (cmd.all) dialog = Dialog.ConfirmNuke(null, "everything")
            else if (room == null) needRoom() else dialog = Dialog.ConfirmNuke(room, "#${s.current?.name}")
            Cmd.Files -> if (room == null) needRoom() else Commx.request("files", "room_id" to room)
            Cmd.Call -> if (room == null) needRoom() else startCall(room)
            Cmd.Hangup -> s.callRoom?.let { Commx.request("hangup", "room_id" to it) } ?: Commx.notify("you're not in a call", true)
            Cmd.Mute -> Commx.setMuted(!s.muted)
            Cmd.Ptt -> Commx.setPtt(!s.ptt)
            Cmd.Status -> { Commx.request("status"); Commx.request("alias_list") }
            Cmd.Help -> { HELP.forEach { Commx.notify(it, false) }; Commx.select(null) }
        }
    }

    // Show freshly created invites right away.
    LaunchedEffect(s.invites) {
        val r = s.selected
        val code = r?.let { s.invites[it] }
        if (code != null && dialog == null && s.current?.isHost == true) dialog = Dialog.Invite(code)
    }

    MaterialTheme(colorScheme = darkColorScheme(primary = Accent, background = Bg, surface = Panel, error = Danger)) {
        Surface(Modifier.fillMaxSize(), color = Bg) {
            Box(Modifier.safeDrawingPadding().imePadding()) {
                when {
                    !s.started -> Centered("starting your node…")
                    s.alias == null -> Onboarding(s) { name, eph, pass ->
                        if (eph) Commx.request("alias_new", "name" to name, "ephemeral" to true, "passphrase" to null)
                        else Commx.request("alias_new", "name" to name, "ephemeral" to false, "passphrase" to pass)
                    }
                    else -> Main(s, ::run, onDialog = { dialog = it }, quit = quit, startCall = ::startCall)
                }
            }
            when (val d = dialog) {
                Dialog.NewRoom -> NewRoomDialog(onDismiss = { dialog = null }) { name, any, grace ->
                    dialog = null
                    run(Cmd.RoomNew(name, any, grace))
                }
                Dialog.Join -> JoinDialog(pasteText, onDismiss = { dialog = null }) { code ->
                    dialog = null
                    run(Cmd.Join(code.trim()))
                }
                is Dialog.Invite -> {
                    val reusable = d.code.startsWith("cx2:")
                    val roomId = s.selected
                    AlertDialog(
                        onDismissRequest = { dialog = null },
                        title = { Text(if (reusable) "Reusable invite (password)" else "Invite (single use, 10 min)") },
                        text = {
                            Column {
                                Text(
                                    if (reusable) "Works until the room ends or you revoke it, only with the password. Send the password over a different channel."
                                    else "Send it over a channel you trust. It stops working once used.",
                                    color = Dim,
                                )
                                Spacer(Modifier.height(8.dp))
                                Text(d.code, fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = Accent)
                                if (roomId != null) Row {
                                    if (!reusable) TextButton(onClick = { dialog = Dialog.InvitePassword(roomId) }) { Text("Make reusable…") }
                                    else TextButton(onClick = { Commx.request("invite_revoke", "room_id" to roomId); dialog = null }) { Text("Revoke", color = Danger) }
                                    TextButton(onClick = { Commx.request("invite", "room_id" to roomId); dialog = null }) { Text("New single-use") }
                                }
                            }
                        },
                        confirmButton = { Button(onClick = { copySecret("commx invite", d.code); Commx.notify("invite copied", false); dialog = null }) { Text("Copy") } },
                        dismissButton = { TextButton(onClick = { dialog = null }) { Text("Close") } },
                    )
                }
                is Dialog.InvitePassword -> SecretDialog(
                    title = "Reusable invite",
                    hint = "Anyone with the invite and this password can join until the room ends. 8+ characters.",
                    minLen = 8,
                    onDismiss = { dialog = null },
                ) { pw ->
                    dialog = null
                    Commx.request("invite_password", "room_id" to d.roomId, "password" to pw)
                }
                is Dialog.JoinPassword -> SecretDialog(
                    title = "Invite password",
                    hint = "This invite is protected by a password. Ask whoever sent it.",
                    minLen = 1,
                    onDismiss = { dialog = null },
                ) { pw ->
                    dialog = null
                    Commx.request("join", "code" to d.code, "password" to pw)
                }
                is Dialog.ConfirmNuke -> AlertDialog(
                    onDismissRequest = { dialog = null },
                    title = { Text("Nuke ${d.label}?") },
                    text = { Text(if (d.roomId == null) "Every room is destroyed, for everyone you host. This can't be undone." else "The room is destroyed. If you host it, it's gone for everyone.") },
                    confirmButton = {
                        Button(colors = ButtonDefaults.buttonColors(containerColor = Danger), onClick = {
                            Commx.request("nuke", "room_id" to d.roomId)
                            dialog = null
                        }) { Text("Nuke") }
                    },
                    dismissButton = { TextButton(onClick = { dialog = null }) { Text("Cancel") } },
                )
                is Dialog.Passphrase -> PassphraseDialog(d.newAlias, onDismiss = { dialog = null }) { pass ->
                    dialog = null
                    if (d.newAlias != null) Commx.request("alias_new", "name" to d.newAlias, "ephemeral" to false, "passphrase" to pass)
                    else Commx.request("unlock", "passphrase" to pass)
                }
                null -> {}
            }
        }
    }
}

@Composable
private fun Centered(text: String) = Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { Text(text, color = Dim) }

@Composable
private fun Onboarding(s: AppState, create: (String, Boolean, String) -> Unit) {
    var name by remember { mutableStateOf("") }
    var ephemeral by remember { mutableStateOf(true) }
    var pass by remember { mutableStateOf("") }
    var unlock by remember { mutableStateOf("") }
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(Modifier.width(420.dp).padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("commx", style = MaterialTheme.typography.headlineMedium, color = Accent)
            Text("End-to-end encrypted, peer-to-peer, memory-only. Pick an alias — no accounts, no phone number.", color = Dim)
            OutlinedTextField(name, { name = it.filter { c -> !c.isWhitespace() }.take(32) }, label = { Text("alias") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            Row(verticalAlignment = Alignment.CenterVertically) {
                Switch(ephemeral, { ephemeral = it })
                Spacer(Modifier.width(8.dp))
                Text(if (ephemeral) "RAM only — gone when the app stops" else "Saved on this device, passphrase-encrypted")
            }
            if (!ephemeral) {
                OutlinedTextField(pass, { pass = it }, label = { Text("passphrase (8+ chars)") }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password), modifier = Modifier.fillMaxWidth())
            }
            Button(enabled = name.isNotEmpty() && (ephemeral || pass.length >= 8), onClick = { create(name, ephemeral, pass) }, modifier = Modifier.fillMaxWidth()) {
                Text("Create alias")
            }
            HorizontalDivider()
            Text("Have saved aliases?", color = Dim)
            OutlinedTextField(unlock, { unlock = it }, label = { Text("passphrase") }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password), modifier = Modifier.fillMaxWidth())
            OutlinedButton(enabled = unlock.isNotEmpty(), onClick = { Commx.request("unlock", "passphrase" to unlock); unlock = "" }, modifier = Modifier.fillMaxWidth()) {
                Text("Unlock")
            }
            s.notice?.let { Text(it.text, color = if (it.error) Danger else Accent) }
        }
    }
}

@Composable
private fun Main(s: AppState, run: (Cmd) -> Unit, onDialog: (Dialog) -> Unit, quit: () -> Unit, startCall: (String) -> Unit) {
    BoxWithConstraints(Modifier.fillMaxSize()) {
        val wide = maxWidth >= 720.dp
        if (wide) {
            Row(Modifier.fillMaxSize()) {
                Sidebar(s, Modifier.width(280.dp).fillMaxHeight(), onDialog, quit)
                Box(Modifier.width(1.dp).fillMaxHeight().background(Panel))
                Conversation(s, run, onDialog, startCall, Modifier.fillMaxSize(), showBack = false)
            }
        } else if (s.selected == null) {
            Sidebar(s, Modifier.fillMaxSize(), onDialog, quit)
        } else {
            Conversation(s, run, onDialog, startCall, Modifier.fillMaxSize(), showBack = true)
        }
    }
}

@Composable
private fun Sidebar(s: AppState, modifier: Modifier, onDialog: (Dialog) -> Unit, quit: () -> Unit) {
    Column(modifier.background(Panel).padding(12.dp)) {
        Text("commx", style = MaterialTheme.typography.titleLarge, color = Accent)
        Text("${s.alias} · ${s.fingerprint}", color = Dim, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
        Spacer(Modifier.height(12.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { onDialog(Dialog.NewRoom) }) { Text("New room") }
            OutlinedButton(onClick = { onDialog(Dialog.Join) }) { Text("Join") }
        }
        Spacer(Modifier.height(12.dp))
        RoomRow("~ home", selected = s.selected == null, unread = false, badge = null) { Commx.select(null) }
        LazyColumn(Modifier.weight(1f)) {
            items(s.rooms, key = { it.id }) { r ->
                val badge = buildString {
                    if (r.anyMember) append("☢ ")
                    if (r.isHost) append("host ")
                    if (s.calls[r.id] != null) append("📞")
                }
                RoomRow("${if (r.isDm) "@" else "#"} ${r.name}", s.selected == r.id, r.id in s.unread, badge.ifBlank { null }) { Commx.select(r.id) }
            }
        }
        Text(s.network, color = Dim, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { onDialog(Dialog.ConfirmNuke(null, "everything")) }) { Text("Nuke all", color = Danger) }
            TextButton(onClick = quit) { Text("Quit", color = Dim) }
        }
    }
}

@Composable
private fun RoomRow(label: String, selected: Boolean, unread: Boolean, badge: String?, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp))
            .background(if (selected) Color(0xFF243630) else Color.Transparent)
            .clickable(onClick = onClick).padding(horizontal = 10.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, color = if (selected) Accent else Color.White, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis,
            fontWeight = if (unread) FontWeight.Bold else FontWeight.Normal)
        badge?.let { Text(it, color = if (it.startsWith("☢")) Danger else Dim, fontSize = 12.sp) }
        if (unread) Box(Modifier.padding(start = 6.dp).size(8.dp).clip(CircleShape).background(Accent))
    }
}

@Composable
private fun Conversation(s: AppState, run: (Cmd) -> Unit, onDialog: (Dialog) -> Unit, startCall: (String) -> Unit, modifier: Modifier, showBack: Boolean) {
    val room = s.current
    Column(modifier.padding(12.dp)) {
        if (room == null) {
            Text("~ home", style = MaterialTheme.typography.titleMedium, color = Accent)
            LazyColumn(Modifier.weight(1f), reverseLayout = true) {
                items(s.home.reversed()) { n -> Text(n.text, color = if (n.error) Danger else Color.White, fontSize = 14.sp) }
                items(HELP.reversed()) { Text(it, color = Dim, fontSize = 13.sp, fontFamily = FontFamily.Monospace) }
            }
        } else {
            RoomHeader(s, room, onDialog, startCall, showBack)
            val lines = s.lines[room.id] ?: emptyList()
            val list = rememberLazyListState()
            LazyColumn(Modifier.weight(1f).fillMaxWidth(), state = list, reverseLayout = true) {
                items(lines.reversed()) { LineView(it) }
            }
        }
        s.notice?.let {
            Text(it.text, color = if (it.error) Danger else Accent, fontSize = 13.sp, modifier = Modifier.padding(vertical = 4.dp).clickable { Commx.clearNotice() })
        }
        InputBar(room, run)
    }
}

@Composable
private fun RoomHeader(s: AppState, room: RoomUi, onDialog: (Dialog) -> Unit, startCall: (String) -> Unit, showBack: Boolean) {
    val call = s.calls[room.id]
    Column(Modifier.fillMaxWidth().padding(bottom = 8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            if (showBack) TextButton(onClick = { Commx.select(null) }) { Text("‹") }
            Column(Modifier.weight(1f)) {
                Text("${if (room.isDm) "@" else "#"}${room.name}", style = MaterialTheme.typography.titleMedium, color = Accent)
                Text(
                    "kill: ${if (room.anyMember) "any-member" else "host-only"} ${room.grace}s · ${room.members.joinToString(", ")}",
                    color = if (room.anyMember) Danger else Dim, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis,
                )
            }
            if (room.isHost) TextButton(onClick = {
                s.invites[room.id]?.let { onDialog(Dialog.Invite(it)) } ?: Commx.request("invite", "room_id" to room.id)
            }) { Text("Invite") }
            when {
                call == null || !call.joined -> TextButton(onClick = { startCall(room.id) }) { Text(if (call == null) "Call" else "Join call") }
                else -> TextButton(onClick = { Commx.request("hangup", "room_id" to room.id) }) { Text("Hang up", color = Danger) }
            }
            TextButton(onClick = { onDialog(Dialog.ConfirmNuke(room.id, "#${room.name}")) }) { Text("Nuke", color = Danger) }
        }
        if (call != null) CallBar(s, call.participants, call.joined, room)
    }
}

@Composable
private fun CallBar(s: AppState, participants: List<String>, joined: Boolean, room: RoomUi) {
    Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(10.dp)).background(Color(0xFF1C2B26)).padding(10.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("📞 ", color = Accent)
            participants.forEachIndexed { i, p ->
                val me = joined && p == room.alias
                val talking = if (me) s.micOpen && s.micLevel > 0.02f else p in s.speaking
                if (i > 0) Text(", ", color = Dim)
                Text(if (talking) "● $p" else p, color = if (talking) Accent else Color.White, fontWeight = if (talking) FontWeight.Bold else FontWeight.Normal)
            }
            Spacer(Modifier.weight(1f))
            if (joined) Text("(${room.link})", color = Dim, fontSize = 12.sp)
        }
        if (joined) {
            Spacer(Modifier.height(8.dp))
            LinearProgressIndicator(progress = { (s.micLevel * 6f).coerceIn(0f, 1f) }, modifier = Modifier.fillMaxWidth(), color = if (s.micOpen) Accent else Dim)
            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { Commx.setMuted(!s.muted) }) { Text(if (s.muted) "Unmute" else "Mute", color = if (s.muted) Danger else Color.White) }
                OutlinedButton(onClick = { Commx.setPtt(!s.ptt) }) { Text(if (s.ptt) "Push-to-talk: on" else "Push-to-talk: off") }
                if (s.ptt) {
                    // Hold to talk. Releasing (or dragging off) closes the mic.
                    Box(
                        Modifier.clip(RoundedCornerShape(20.dp)).background(if (s.talking) Accent else Color(0xFF2E4A40))
                            .pointerInput(Unit) {
                                awaitEachGesture {
                                    awaitFirstDown()
                                    Commx.setTalking(true)
                                    waitForUpOrCancellation()
                                    Commx.setTalking(false)
                                }
                            }.padding(horizontal = 20.dp, vertical = 10.dp),
                    ) { Text(if (s.talking) "Talking…" else "Hold to talk", color = if (s.talking) Color.Black else Color.White) }
                }
            }
        }
    }
}

@Composable
private fun LineView(l: Line) {
    Row(Modifier.padding(vertical = 2.dp)) {
        Text(time(l.tsMin) + " ", color = Dim, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
        when {
            l.local -> Text(l.text, color = Dim, fontStyle = FontStyle.Italic, fontSize = 14.sp)
            l.system -> Text("* ${l.text}", color = Color(0xFFE6C86E), fontStyle = FontStyle.Italic, fontSize = 14.sp)
            else -> {
                Text(l.from + " ", color = if (l.mine) Accent else nameColor(l.from), fontWeight = FontWeight.Bold, fontSize = 14.sp)
                Text(l.text, color = Color.White, fontSize = 14.sp)
            }
        }
    }
}

@Composable
private fun InputBar(room: RoomUi?, run: (Cmd) -> Unit) {
    var text by remember { mutableStateOf("") }
    fun submit() {
        val t = text.trim()
        if (t.isEmpty()) return
        parseCmd(t).fold(onSuccess = run, onFailure = { Commx.notify(it.message ?: "bad command", true) })
        text = ""
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        OutlinedTextField(
            value = text,
            onValueChange = { text = it },
            placeholder = { Text(if (room == null) "command (/help)" else "message ${if (room.isDm) "@" else "#"}${room.name}") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send, autoCorrectEnabled = false),
            keyboardActions = KeyboardActions(onSend = { submit() }),
            // Hardware keyboard: Enter sends.
            modifier = Modifier.weight(1f).onPreviewKeyEvent { e ->
                if (e.type == KeyEventType.KeyDown && (e.key == Key.Enter || e.key == Key.NumPadEnter) && !e.isShiftPressed) {
                    submit(); true
                } else false
            },
        )
        Spacer(Modifier.width(8.dp))
        Button(onClick = ::submit) { Text("Send") }
    }
}

@Composable
private fun NewRoomDialog(onDismiss: () -> Unit, create: (String, Boolean, Long) -> Unit) {
    var name by remember { mutableStateOf("") }
    var any by remember { mutableStateOf(false) }
    var grace by remember { mutableStateOf(15f) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("New room") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(name, { name = it.take(48) }, label = { Text("name") }, singleLine = true)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(any, { any = it })
                    Spacer(Modifier.width(8.dp))
                    Text(if (any) "☢ any member dropping nukes the room" else "only the host dropping nukes the room", color = if (any) Danger else Dim)
                }
                Text("grace: ${grace.toInt()} s before a silent peer counts as dropped", color = Dim)
                Slider(grace, { grace = it }, valueRange = 5f..120f)
            }
        },
        confirmButton = { Button(enabled = name.isNotBlank(), onClick = { create(name.trim(), any, grace.toLong()) }) { Text("Create") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun JoinDialog(pasteText: () -> String?, onDismiss: () -> Unit, join: (String) -> Unit) {
    var code by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Join a room") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(code, { code = it }, label = { Text("invite (cx1:... or cx2:...)") }, maxLines = 4)
                TextButton(onClick = { pasteText()?.let { code = it.trim() } }) { Text("Paste") }
            }
        },
        confirmButton = { Button(enabled = code.trim().let { it.startsWith("cx1:") || it.startsWith("cx2:") }, onClick = { join(code) }) { Text("Join") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun PassphraseDialog(newAlias: String?, onDismiss: () -> Unit, done: (String) -> Unit) {
    var pass by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (newAlias != null) "Passphrase for '$newAlias'" else "Unlock saved aliases") },
        text = {
            OutlinedTextField(pass, { pass = it }, label = { Text("passphrase") }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password))
        },
        confirmButton = { Button(enabled = pass.length >= (if (newAlias != null) 8 else 1), onClick = { done(pass) }) { Text("OK") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun SecretDialog(title: String, hint: String, minLen: Int, onDismiss: () -> Unit, done: (String) -> Unit) {
    var pass by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(hint, color = Dim)
                OutlinedTextField(pass, { pass = it }, label = { Text("password") }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password))
            }
        },
        confirmButton = { Button(enabled = pass.length >= minLen, onClick = { done(pass) }) { Text("OK") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
