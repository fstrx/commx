package io.github.fstrx.commx

/** Slash commands from the input box, same as the desktop TUI. */
sealed interface Cmd {
    data class Say(val text: String) : Cmd
    data class AliasNew(val name: String, val ephemeral: Boolean) : Cmd
    data class AliasUse(val name: String) : Cmd
    data object AliasList : Cmd
    data object Unlock : Cmd
    data class RoomNew(val name: String, val anyMember: Boolean, val grace: Long) : Cmd
    data class Dm(val label: String) : Cmd
    data object Invite : Cmd
    data class Join(val code: String) : Cmd
    data class Nuke(val all: Boolean) : Cmd
    data object Files : Cmd
    data object Call : Cmd
    data object Hangup : Cmd
    data object Mute : Cmd
    data object Ptt : Cmd
    data object Status : Cmd
    data object Help : Cmd
}

val HELP = listOf(
    "/alias new <name> [--ephemeral]   ·   /alias use <name>   ·   /aliases   ·   /unlock",
    "/room new <name> [--any-member] [--grace N]   ·   /dm <label>",
    "/invite   ·   /join <cx1:...>   ·   /files",
    "/call   ·   /hangup   ·   /mute   ·   /ptt (hold the talk button)",
    "/nuke (this room)   ·   /nuke all   ·   /status",
)

fun parseCmd(input: String): Result<Cmd> {
    val t = input.trim()
    if (!t.startsWith("/")) return Result.success(Cmd.Say(t))
    val w = t.split(Regex("\\s+"))
    val rest = w.drop(1)
    fun usage(u: String) = Result.failure<Cmd>(IllegalArgumentException("usage: $u"))
    return when (w[0]) {
        "/help", "/h" -> Result.success(Cmd.Help)
        "/status", "/fp" -> Result.success(Cmd.Status)
        "/unlock" -> Result.success(Cmd.Unlock)
        "/aliases" -> Result.success(Cmd.AliasList)
        "/alias" -> when {
            rest.firstOrNull() == "list" -> Result.success(Cmd.AliasList)
            rest.size == 2 && rest[0] == "use" -> Result.success(Cmd.AliasUse(rest[1]))
            rest.size >= 2 && rest[0] == "new" ->
                Result.success(Cmd.AliasNew(rest[1], rest.drop(2).any { it == "--ephemeral" || it == "-e" }))
            else -> usage("/alias new <name> [--ephemeral] | use <name> | list")
        }
        "/room" -> {
            if (rest.firstOrNull() != "new") return usage("/room new <name> [--any-member] [--grace N]")
            var any = false
            var grace = 15L
            val name = mutableListOf<String>()
            val it = rest.drop(1).iterator()
            while (it.hasNext()) {
                when (val a = it.next()) {
                    "--any-member", "--any" -> any = true
                    "--host-only" -> any = false
                    "--grace" -> grace = (if (it.hasNext()) it.next().toLongOrNull() else null)
                        ?: return Result.failure(IllegalArgumentException("--grace needs a number of seconds"))
                    else -> name += a
                }
            }
            if (name.isEmpty()) usage("/room new <name> [--any-member] [--grace N]")
            else Result.success(Cmd.RoomNew(name.joinToString(" "), any, grace))
        }
        "/dm" -> if (rest.isEmpty()) usage("/dm <label>") else Result.success(Cmd.Dm(rest.joinToString(" ")))
        "/invite" -> Result.success(Cmd.Invite)
        "/join" -> if (rest.size == 1) Result.success(Cmd.Join(rest[0])) else usage("/join <cx1:...>")
        "/nuke" -> when (rest) {
            emptyList<String>() -> Result.success(Cmd.Nuke(false))
            listOf("all") -> Result.success(Cmd.Nuke(true))
            else -> usage("/nuke [all]")
        }
        "/files" -> Result.success(Cmd.Files)
        "/call", "/vc" -> Result.success(Cmd.Call)
        "/hangup", "/leave" -> Result.success(Cmd.Hangup)
        "/mute", "/unmute" -> Result.success(Cmd.Mute)
        "/ptt" -> Result.success(Cmd.Ptt)
        else -> Result.failure(IllegalArgumentException("unknown command ${w[0]} (try /help)"))
    }
}
