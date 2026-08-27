"""
Discord bot that issues app-owned, signed tokens in the JSON format shown
in the reference recording.

These are NOT Discord user/bot tokens and cannot be used to log in to Discord.
They are JWT-like credentials for an application or API that you control.
Keep DISCORD_BOT_TOKEN and TOKEN_SECRET in environment variables.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

import discord
from discord import app_commands


# Configuration is intentionally read from the environment instead of being
# committed to source control.
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")
TOKEN_SECRET = os.environ.get("TOKEN_SECRET", "")
TOKEN_NOTE = os.environ.get("TOKEN_NOTE", "Made by mestro_ac and forest")

# Keep runtime data beside this bot by default, even when the command is
# launched from the monorepo root or by a workflow with a different cwd.
DEFAULT_TOKEN_DIR = Path(__file__).resolve().parent / "tokens"
TOKEN_DIR = Path(os.environ.get("TOKEN_DIR", str(DEFAULT_TOKEN_DIR)))
TOKEN_DIR.mkdir(parents=True, exist_ok=True)
ADDED_TOKEN_FILE = TOKEN_DIR / "added_tokens.json"

TOKEN_LIFETIME_SECONDS = int(os.environ.get("TOKEN_LIFETIME_SECONDS", "3600"))
COOLDOWN_SECONDS = int(os.environ.get("COOLDOWN_SECONDS", "1200"))
ALLOWED_CHANNEL_ID = int(os.environ.get("ALLOWED_CHANNEL_ID", "0"))
TOKEN_PANEL_CHANNEL_ID = int(
    os.environ.get("TOKEN_PANEL_CHANNEL_ID", str(ALLOWED_CHANNEL_ID))
)
# The supplied value is a Discord role ID, not a user ID.
OWNER_ROLE_ID = 1541910111361179778
# An optional owner account ID can still be configured separately.
OWNER_ID = int(os.environ.get("OWNER_ID", "0"))
ADMIN_ID = int(os.environ.get("ADMIN_ID", "0"))
CO_OWNER_IDS = {
    int(value.strip())
    for value in os.environ.get(
        "CO_OWNER_IDS",
        os.environ.get("CO_OWNER_ID", ""),
    ).split(",")
    if value.strip().isdigit()
}
BOOSTER_ROLE_ID = int(os.environ.get("BOOSTER_ROLE_ID", "0"))
BUYER_ROLE_ID = int(os.environ.get("BUYER_ROLE_ID", "0"))
VIP_ROLE_ID = int(os.environ.get("VIP_ROLE_ID", "0"))
ONE_MINUTE_ROLE_ID = int(
    os.environ.get("ONE_MINUTE_ROLE_ID", "1541938948224581783")
)
BOOSTER_COOLDOWN_SECONDS = int(
    os.environ.get("BOOSTER_COOLDOWN_SECONDS", "600")
)
BUYER_COOLDOWN_SECONDS = int(os.environ.get("BUYER_COOLDOWN_SECONDS", "360"))
VIP_COOLDOWN_SECONDS = int(os.environ.get("VIP_COOLDOWN_SECONDS", "240"))
PANEL_HEADLINE = os.environ.get(
    "PANEL_HEADLINE",
    "Generate your EIC token below!",
)
PANEL_TITLE = os.environ.get("PANEL_TITLE", "envo token generator")
PANEL_FOOTER = os.environ.get("PANEL_FOOTER", "Made by mestro")
# This bot is intentionally hard-locked to this server. Do not make this
# configurable: changing it through an environment variable would allow the
# bot to operate in a different server.
AUTHORIZED_GUILD_ID = 1541905046520995983
DONATION_SERVER_INVITE = os.environ.get(
    "DONATION_SERVER_INVITE",
    "https://discord.gg/eicmodding",
)
MAX_BULK_TOKEN_PAIRS = 49
BULK_SESSION_TIMEOUT_SECONDS = 15 * 60
# Bulk-add sessions are intentionally short-lived and in memory. The token
# pairs themselves are persisted only after each validated batch is submitted.
_BULK_SESSIONS: dict[int, dict[str, int]] = {}


def _sign_app_token(user_id: int, token_type: str, expires_at: int) -> str:
    """Create an app-owned HS256 token with a JWT-compatible three-part shape."""
    now = int(time.time())
    header = _b64(json.dumps(
        {"alg": "HS256", "typ": "JWT"},
        separators=(",", ":"),
    ).encode())
    payload = _b64(json.dumps(
        {
            "uid": str(user_id),
            "tid": token_type,
            "exp": expires_at,
            "iat": now,
            "jti": secrets.token_hex(16),
        },
        separators=(",", ":"),
    ).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = _b64(hmac.new(
        TOKEN_SECRET.encode("utf-8"),
        signing_input,
        hashlib.sha256,
    ).digest())
    return f"{header}.{payload}.{signature}"


def _user_file(user_id: int) -> Path:
    return TOKEN_DIR / f"{user_id}.json"


def _panel_state_file() -> Path:
    return TOKEN_DIR / "panel.json"


def _load_user(user_id: int) -> dict[str, Any] | None:
    path = _user_file(user_id)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _save_user(user_id: int, data: dict[str, Any]) -> None:
    # Replace the file atomically so a partial write cannot corrupt a token
    # record if the process stops while saving.
    path = _user_file(user_id)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
    temporary.replace(path)


def _load_panel_state() -> dict[str, Any]:
    path = _panel_state_file()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return {}


def _load_panel_message_id() -> int | None:
    message_id = _load_panel_state().get("message_id")
    try:
        return int(message_id) if message_id else None
    except (TypeError, ValueError):
        return None


def _load_panel_channel_id() -> int:
    channel_id = _load_panel_state().get("channel_id")
    try:
        if channel_id:
            return int(channel_id)
    except (TypeError, ValueError):
        pass
    return TOKEN_PANEL_CHANNEL_ID


def _save_panel_state(state: dict[str, Any]) -> None:
    path = _panel_state_file()
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, indent=2), encoding="utf-8")
    temporary.replace(path)


def _save_panel_channel_id(channel_id: int) -> None:
    state = _load_panel_state()
    if state.get("channel_id") != str(channel_id):
        state.pop("message_id", None)
    state["channel_id"] = str(channel_id)
    _save_panel_state(state)


def _save_panel_message_id(message_id: int) -> None:
    state = _load_panel_state()
    state["message_id"] = str(message_id)
    _save_panel_state(state)


def _reset_all_cooldowns() -> tuple[int, int]:
    """Clear issuance timestamps while preserving each user's token data."""
    reset_count = 0
    skipped_count = 0
    for path in TOKEN_DIR.glob("*.json"):
        if path == ADDED_TOKEN_FILE:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                continue
            changed = False
            if "last_issued" in data:
                data["last_issued"] = 0
                changed = True
            stored_tokens = data.get("tokens")
            if isinstance(stored_tokens, dict):
                for token_record in stored_tokens.values():
                    if isinstance(token_record, dict) and "last_issued" in token_record:
                        token_record["last_issued"] = 0
                        changed = True
            if not changed:
                continue
            temporary = path.with_suffix(".tmp")
            temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
            temporary.replace(path)
            reset_count += 1
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            skipped_count += 1
    return reset_count, skipped_count


def _load_added_tokens() -> list[dict[str, Any]]:
    """Load the bearer/refresh token pairs added by administrators."""
    if not ADDED_TOKEN_FILE.exists():
        return []
    try:
        data = json.loads(ADDED_TOKEN_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return data if isinstance(data, list) else []


def _save_added_tokens(records: list[dict[str, Any]]) -> None:
    """Persist the token stock without exposing credentials in Discord."""
    temporary = ADDED_TOKEN_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps(records, indent=2), encoding="utf-8")
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    temporary.replace(ADDED_TOKEN_FILE)


def _save_added_token(
    bearer_token: str,
    refresh_token: str,
    added_by: discord.abc.User,
    source: str = "admin",
    source_guild_id: int | None = None,
) -> int:
    """Append a token pair without returning either secret to the caller."""
    return _save_added_token_pairs(
        [(bearer_token, refresh_token)],
        added_by,
        source=source,
        source_guild_id=source_guild_id,
    )


def _save_added_token_pairs(
    token_pairs: list[tuple[str, str]],
    added_by: discord.abc.User,
    source: str = "admin",
    source_guild_id: int | None = None,
) -> int:
    """Append several token pairs in one atomic stock-file update."""
    records = _load_added_tokens()
    added_at = int(time.time())
    for bearer_token, refresh_token in token_pairs:
        record: dict[str, Any] = {
            "id": secrets.token_hex(12),
            "bearer_token": bearer_token,
            "refresh_token": refresh_token,
            "added_by": str(added_by.id),
            "added_at": added_at,
            "source": source,
        }
        if source_guild_id is not None:
            record["source_guild_id"] = str(source_guild_id)
        records.append(record)
    _save_added_tokens(records)
    return len(records)


def _bulk_session_count(user_id: int) -> int:
    """Return the current bulk-add count, removing expired sessions."""
    session = _BULK_SESSIONS.get(user_id)
    if not session:
        return 0
    if int(time.time()) - session["started_at"] >= BULK_SESSION_TIMEOUT_SECONDS:
        _BULK_SESSIONS.pop(user_id, None)
        return 0
    return session["added_count"]


def _start_bulk_session(user_id: int) -> int:
    """Start or resume a short-lived bulk-add session for one owner."""
    count = _bulk_session_count(user_id)
    if user_id not in _BULK_SESSIONS:
        _BULK_SESSIONS[user_id] = {
            "started_at": int(time.time()),
            "added_count": 0,
        }
    return count


def _seconds_left(timestamp: int) -> int:
    return max(0, int(timestamp - time.time()))


TOKEN_POLICIES: dict[str, dict[str, Any]] = {
    "public": {
        "label": "Public Token",
        "emoji": "🌍",
        "role_id": 0,
        "cooldown_seconds": COOLDOWN_SECONDS,
        "style": discord.ButtonStyle.success,
    },
    "booster": {
        "label": "Booster Token",
        "emoji": "🚀",
        "role_id": BOOSTER_ROLE_ID,
        "cooldown_seconds": BOOSTER_COOLDOWN_SECONDS,
        "style": discord.ButtonStyle.primary,
    },
    "buyer": {
        "label": "Buyer Token",
        "emoji": "🛒",
        "role_id": BUYER_ROLE_ID,
        "cooldown_seconds": BUYER_COOLDOWN_SECONDS,
        "style": discord.ButtonStyle.secondary,
    },
    "vip": {
        "label": "VIP Token",
        "emoji": "⚡",
        "role_id": VIP_ROLE_ID,
        "cooldown_seconds": VIP_COOLDOWN_SECONDS,
        "style": discord.ButtonStyle.secondary,
    },
    "one_minute": {
        "label": "1 Minute Token",
        "emoji": "⏱️",
        "role_id": ONE_MINUTE_ROLE_ID,
        "cooldown_seconds": 60,
        "style": discord.ButtonStyle.success,
    },
}


def _format_duration(seconds: int) -> str:
    minutes, remaining_seconds = divmod(max(0, seconds), 60)
    return f"{minutes}m {remaining_seconds}s"


def _has_role(interaction: discord.Interaction, role_id: int) -> bool:
    return (
        role_id != 0
        and isinstance(interaction.user, discord.Member)
        and any(role.id == role_id for role in interaction.user.roles)
    )


def _policy_for(token_type: str) -> dict[str, Any]:
    return TOKEN_POLICIES[token_type]


def _role_text(role_id: int) -> str:
    return f"<@&{role_id}>" if role_id else "role not configured"


def _stored_token_record(
    stored: dict[str, Any],
    token_type: str,
) -> dict[str, Any] | None:
    """Read new per-type records and migrate the original public record."""
    token_records = stored.get("tokens")
    if isinstance(token_records, dict):
        record = token_records.get(token_type)
        if isinstance(record, dict):
            return record

    # The original bot stored a single public record at the top level.
    if token_type == "public" and "token" in stored:
        return {
            "token": stored.get("token"),
            "refresh_token": stored.get("refresh_token"),
            "expires_at": stored.get("expires_at", 0),
            "last_issued": stored.get("last_issued", 0),
            "cooldown_seconds": stored.get(
                "cooldown_seconds",
                COOLDOWN_SECONDS,
            ),
        }
    return None


def _panel_embed() -> discord.Embed:
    public_policy = _policy_for("public")
    booster_policy = _policy_for("booster")
    buyer_policy = _policy_for("buyer")
    vip_policy = _policy_for("vip")
    one_minute_policy = _policy_for("one_minute")

    description = (
        f"**{PANEL_HEADLINE}**\n\n"
        f"**Public Token** — everyone | cooldown: "
        f"`{_format_duration(public_policy['cooldown_seconds'])}`\n"
        f"**Booster Token** — {_role_text(booster_policy['role_id'])} only | "
        f"cooldown: `{_format_duration(booster_policy['cooldown_seconds'])}`\n"
        f"**Buyer Token** — {_role_text(buyer_policy['role_id'])} only | "
        f"cooldown: `{_format_duration(buyer_policy['cooldown_seconds'])}`\n"
        f"**VIP Token** — {_role_text(vip_policy['role_id'])} only | "
        f"cooldown: `{_format_duration(vip_policy['cooldown_seconds'])}`\n\n"
        f"**1 Minute Token** — {_role_text(one_minute_policy['role_id'])} only | "
        f"cooldown: `{_format_duration(one_minute_policy['cooldown_seconds'])}`\n\n"
        "**Add Token** — owner only | add token stock\n\n"
        f"**Multiple Tokens Add** — owner role only | up to "
        f"`{MAX_BULK_TOKEN_PAIRS}` token pairs per session\n\n"
        "Tokens are only visible to you.\n"
        "*Ephemeral — only you can see your token*"
    )
    embed = discord.Embed(
        title=PANEL_TITLE,
        description=description,
        colour=discord.Colour.blurple(),
    )
    embed.set_footer(text=PANEL_FOOTER)
    return embed


def _make_response_json(
    token: str,
    refresh_token: str,
    expires_at: int,
    next_use_in: int,
) -> str:
    """Build the exact user-facing shape from the reference recording."""
    return json.dumps(
        {
            "token": token,
            "refresh_token": refresh_token,
            "expires_in": _seconds_left(expires_at),
            "next_use_in": max(0, next_use_in),
            "note": TOKEN_NOTE,
        },
        indent=4,
    )


def _channel_is_allowed(interaction: discord.Interaction) -> bool:
    return ALLOWED_CHANNEL_ID == 0 or interaction.channel_id == ALLOWED_CHANNEL_ID


async def _check_authorized_guild(interaction: discord.Interaction) -> bool:
    """Reject every interaction outside the owner server, including DMs."""
    if interaction.guild_id == AUTHORIZED_GUILD_ID:
        return True
    await interaction.response.send_message(
        "❌ This bot is authorized only in its designated server.",
        ephemeral=True,
    )
    return False


def _is_owner(interaction: discord.Interaction) -> bool:
    return OWNER_ID != 0 and interaction.user.id == OWNER_ID


def _is_server_owner(interaction: discord.Interaction) -> bool:
    guild = interaction.guild
    return guild is not None and guild.owner_id == interaction.user.id


def _has_owner_role(interaction: discord.Interaction) -> bool:
    return _has_role(interaction, OWNER_ROLE_ID)


def _is_owner_or_co_owner(interaction: discord.Interaction) -> bool:
    return (
        _is_owner(interaction)
        or _is_server_owner(interaction)
        or _has_owner_role(interaction)
        or interaction.user.id in CO_OWNER_IDS
    )


def _is_owner_only(interaction: discord.Interaction) -> bool:
    return (
        _is_owner(interaction)
        or _is_server_owner(interaction)
        or _has_owner_role(interaction)
    )


def _is_admin_or_owner(interaction: discord.Interaction) -> bool:
    """Allow administrators, the owner, the admin ID, or a co-owner."""
    if (
        _is_owner_or_co_owner(interaction)
        or interaction.user.id == ADMIN_ID
    ):
        return True
    return (
        isinstance(interaction.user, discord.Member)
        and interaction.user.guild_permissions.administrator
    )


def _cooldown_seconds_for(interaction: discord.Interaction) -> int:
    """Return the legacy public-token cooldown for compatibility."""
    return int(_policy_for("public")["cooldown_seconds"])


def _token_expiration_error(
    bearer_token: str,
    refresh_token: str,
) -> str | None:
    """Return an error when the supplied JWT credentials cannot be current."""
    now = int(time.time())
    bearer_expiry = _jwt_expiry(bearer_token)
    if bearer_expiry is None:
        return (
            "❌ The bearer token must be a JWT containing an `exp` claim "
            "so its expiration can be checked."
        )
    if bearer_expiry <= now:
        return "❌ The bearer token is expired."

    # Refresh tokens are often opaque. If one is a JWT, check it too; if it
    # is opaque, the provider must be used for deeper revocation validation.
    refresh_expiry = _jwt_expiry(refresh_token)
    if refresh_expiry is not None and refresh_expiry <= now:
        return "❌ The refresh token is expired."
    return None


def _take_stock_token_pair() -> tuple[str, str] | None:
    """Take the first non-expired token pair from the stock queue."""
    records = _load_added_tokens()
    remaining: list[dict[str, Any]] = []
    selected: tuple[str, str] | None = None

    for record in records:
        bearer = record.get("bearer_token") if isinstance(record, dict) else None
        refresh = record.get("refresh_token") if isinstance(record, dict) else None
        if (
            selected is None
            and isinstance(bearer, str)
            and isinstance(refresh, str)
            and not _token_expiration_error(bearer, refresh)
        ):
            selected = bearer, refresh
            continue
        remaining.append(record)

    # Expired or malformed records are removed as the queue is cleaned.
    if len(remaining) != len(records):
        _save_added_tokens(remaining)
    return selected


def _delete_all_tokens() -> tuple[int, int]:
    """Delete token stock and all per-user token records."""
    stock_count = len(_load_added_tokens())
    removed_user_records = 0

    if ADDED_TOKEN_FILE.exists():
        ADDED_TOKEN_FILE.unlink()

    for path in TOKEN_DIR.glob("*.json"):
        if path.name in {ADDED_TOKEN_FILE.name, "panel.json"}:
            continue
        try:
            path.unlink()
            removed_user_records += 1
        except OSError:
            pass

    return stock_count, removed_user_records


async def _donation_server_member(
    user_id: int,
) -> tuple[bool, int | None, str | None]:
    """Resolve the configured invite and verify that the user is a member."""
    try:
        invite = await client.fetch_invite(DONATION_SERVER_INVITE)
    except (discord.HTTPException, discord.NotFound):
        return False, None, "❌ The donation server could not be verified."

    if invite.guild is None:
        return False, None, "❌ The configured invite does not point to a server."

    guild_id = invite.guild.id
    try:
        guild = client.get_guild(guild_id)
        if guild is None:
            guild = await client.fetch_guild(guild_id)
        await guild.fetch_member(user_id)
    except discord.NotFound:
        return (
            False,
            guild_id,
            "❌ You must be a member of the donation server before donating.",
        )
    except discord.Forbidden:
        return (
            False,
            guild_id,
            "❌ The bot cannot verify membership in the donation server. "
            "Make sure the bot is also in that server.",
        )
    except discord.HTTPException:
        return False, guild_id, "❌ The donation server membership check failed."
    return True, guild_id, None


async def _check_access(interaction: discord.Interaction) -> bool:
    if not await _check_authorized_guild(interaction):
        return False
    if _is_owner(interaction) or _channel_is_allowed(interaction):
        return True
    await interaction.response.send_message(
        f"❌ Use the token panel in <#{ALLOWED_CHANNEL_ID}>.",
        ephemeral=True,
    )
    return False


async def _check_admin_or_owner(interaction: discord.Interaction) -> bool:
    if not await _check_authorized_guild(interaction):
        return False
    if _is_admin_or_owner(interaction):
        return True
    await interaction.response.send_message(
        "❌ Only server administrators, the owner, or a configured co-owner "
        "can use this command.",
        ephemeral=True,
    )
    return False


async def _check_owner_or_co_owner(interaction: discord.Interaction) -> bool:
    if not await _check_authorized_guild(interaction):
        return False
    if _is_owner_or_co_owner(interaction):
        return True
    await interaction.response.send_message(
        "❌ Only the owner or a configured co-owner can choose the panel channel.",
        ephemeral=True,
    )
    return False


async def _check_owner_only(interaction: discord.Interaction) -> bool:
    if not await _check_authorized_guild(interaction):
        return False
    if _is_owner_only(interaction):
        return True
    await interaction.response.send_message(
        "❌ Only the owner can add tokens from this panel.",
        ephemeral=True,
    )
    return False


async def _check_owner_role_only(interaction: discord.Interaction) -> bool:
    """Require the configured owner role specifically for bulk adding."""
    if not await _check_authorized_guild(interaction):
        return False
    if _has_owner_role(interaction):
        return True
    await interaction.response.send_message(
        f"❌ Only members with the {_role_text(OWNER_ROLE_ID)} role can use "
        "Multiple Tokens Add.",
        ephemeral=True,
    )
    return False


async def _store_submitted_token_pair(
    interaction: discord.Interaction,
    bearer_token: str,
    refresh_token: str,
    source: str,
    source_guild_id: int | None = None,
) -> None:
    """Validate and store a token pair while keeping values out of replies."""
    bearer = bearer_token.strip()
    if bearer.lower().startswith("bearer "):
        bearer = bearer[7:].strip()
    refresh = refresh_token.strip()

    if len(bearer) < 340 or len(refresh) < 340:
        await interaction.response.send_message(
            "❌ Both tokens must be at least 340 characters long.",
            ephemeral=True,
        )
        return

    expiry_error = _token_expiration_error(bearer, refresh)
    if expiry_error:
        await interaction.response.send_message(expiry_error, ephemeral=True)
        return

    try:
        total = _save_added_token(
            bearer,
            refresh,
            interaction.user,
            source=source,
            source_guild_id=source_guild_id,
        )
    except OSError:
        await interaction.response.send_message(
            "❌ The token pair could not be saved. Try again later.",
            ephemeral=True,
        )
        return

    await interaction.response.send_message(
        f"✅ Token pair added successfully. Stored token pairs: **{total}**.\n"
        "The token values were not displayed in this response.",
        ephemeral=True,
    )


async def _send_token_bundle(
    interaction: discord.Interaction,
    token_json: str,
) -> None:
    """Send both the visible JSON block and token.json, like the recording."""
    attachment = discord.File(
        io.BytesIO(token_json.encode("utf-8")),
        filename="token.json",
    )
    await interaction.response.send_message(
        content=f"```json\n{token_json}\n```",
        file=attachment,
        ephemeral=True,
    )


class TokenBot(discord.Client):
    def __init__(self) -> None:
        intents = discord.Intents.default()
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self) -> None:
        self.add_view(TokenPanelView())
        guild = discord.Object(id=AUTHORIZED_GUILD_ID)
        self.tree.copy_global_to(guild=guild)
        await self.tree.sync(guild=guild)

        # Remove commands that may have been registered globally by an older
        # deployment. The guild copy above remains available only here.
        self.tree.clear_commands(guild=None)
        await self.tree.sync()
        print(f"Commands synced only to authorized guild {AUTHORIZED_GUILD_ID}.")

    async def on_ready(self) -> None:
        await self._ensure_token_panel()
        print(f"Logged in as {self.user}.")

    async def _ensure_token_panel(self, channel_id: int | None = None) -> bool:
        target_channel_id = channel_id or _load_panel_channel_id()
        if target_channel_id == 0:
            print(
                "Token panel is not configured. Use /set channel or set "
                "TOKEN_PANEL_CHANNEL_ID to post the button panel."
            )
            return False

        channel = self.get_channel(target_channel_id)
        if channel is None:
            try:
                channel = await self.fetch_channel(target_channel_id)
            except (discord.Forbidden, discord.HTTPException, discord.NotFound):
                print(
                    "Could not access the configured token panel channel. "
                    "Check the channel ID and bot permissions."
                )
                return False

        if not isinstance(channel, discord.TextChannel):
            print("The token panel channel must be a text channel.")
            return False
        if channel.guild.id != AUTHORIZED_GUILD_ID:
            print(
                "The token panel channel must belong to the authorized guild "
                f"{AUTHORIZED_GUILD_ID}."
            )
            return False

        panel_message_id = _load_panel_message_id()
        if panel_message_id:
            try:
                message = await channel.fetch_message(panel_message_id)
                await message.edit(embed=_panel_embed(), view=TokenPanelView())
                return True
            except discord.NotFound:
                pass
            except (discord.Forbidden, discord.HTTPException):
                print("Could not update the existing token panel message.")
                return False

        try:
            message = await channel.send(embed=_panel_embed(), view=TokenPanelView())
            _save_panel_message_id(message.id)
            print(f"Token panel posted with message ID {message.id}.")
            return True
        except (discord.Forbidden, discord.HTTPException, OSError):
            print(
                "Could not post the token panel. Make sure the bot can "
                "send messages and use application commands in that channel."
            )
            return False


client = TokenBot()


class TokenButton(discord.ui.Button["TokenPanelView"]):
    def __init__(self, token_type: str) -> None:
        policy = _policy_for(token_type)
        super().__init__(
            label=str(policy["label"]),
            style=policy["style"],
            emoji=str(policy["emoji"]),
            custom_id=f"token-panel:{token_type}",
            row=1 if token_type in {"vip", "one_minute"} else 0,
        )
        self.token_type = token_type

    async def callback(self, interaction: discord.Interaction) -> None:
        await issue_token(interaction, self.token_type)


class TokenPanelView(discord.ui.View):
    def __init__(self) -> None:
        super().__init__(timeout=None)
        for token_type in TOKEN_POLICIES:
            self.add_item(TokenButton(token_type))
        self.add_item(AddTokenButton())
        self.add_item(MultipleTokensAddButton())


class AddTokenModal(discord.ui.Modal, title="Add bearer and refresh tokens"):
    bearer_token = discord.ui.TextInput(
        label="Bearer token",
        placeholder="Paste the bearer token here",
        style=discord.TextStyle.paragraph,
        min_length=340,
        max_length=4000,
        required=True,
    )
    refresh_token = discord.ui.TextInput(
        label="Refresh token",
        placeholder="Paste the refresh token here",
        style=discord.TextStyle.paragraph,
        min_length=340,
        max_length=4000,
        required=True,
    )

    async def on_submit(self, interaction: discord.Interaction) -> None:
        if not await _check_authorized_guild(interaction):
            return
        await _store_submitted_token_pair(
            interaction,
            str(self.bearer_token),
            str(self.refresh_token),
            source="admin",
        )


def _split_bulk_token_input(value: str) -> list[str]:
    """Read one token per non-empty line from a bulk modal field."""
    return [line.strip() for line in value.splitlines() if line.strip()]


def _prepare_bulk_token_pairs(
    bearer_text: str,
    refresh_text: str,
    remaining_slots: int,
) -> tuple[list[tuple[str, str]], str | None]:
    """Validate matching bearer/refresh lines without exposing their values."""
    bearer_tokens = _split_bulk_token_input(bearer_text)
    refresh_tokens = _split_bulk_token_input(refresh_text)

    if not bearer_tokens or not refresh_tokens:
        return [], "❌ Enter at least one bearer token and refresh token."
    if len(bearer_tokens) != len(refresh_tokens):
        return (
            [],
            "❌ The number of bearer tokens must match the number of refresh "
            "tokens. Put one token on each line.",
        )
    if len(bearer_tokens) > remaining_slots:
        return (
            [],
            f"❌ This session has room for only **{remaining_slots}** more "
            f"token pair(s). The maximum is **{MAX_BULK_TOKEN_PAIRS}**.",
        )

    pairs: list[tuple[str, str]] = []
    for index, (bearer, refresh) in enumerate(
        zip(bearer_tokens, refresh_tokens),
        start=1,
    ):
        if bearer.lower().startswith("bearer "):
            bearer = bearer[7:].strip()
        if len(bearer) < 340 or len(refresh) < 340:
            return (
                [],
                f"❌ Token pair **#{index}**: both tokens must be at least "
                "340 characters long.",
            )
        expiry_error = _token_expiration_error(bearer, refresh)
        if expiry_error:
            return [], f"❌ Token pair **#{index}** is invalid. {expiry_error[2:]}"
        pairs.append((bearer, refresh))
    return pairs, None


class MultipleTokensModal(
    discord.ui.Modal,
    title="Add multiple token pairs",
):
    bearer_tokens = discord.ui.TextInput(
        label="Bearer tokens, one per line",
        placeholder="Paste one bearer token per line",
        style=discord.TextStyle.paragraph,
        min_length=340,
        max_length=4000,
        required=True,
    )
    refresh_tokens = discord.ui.TextInput(
        label="Refresh tokens, one per line",
        placeholder="Paste the matching refresh token per line",
        style=discord.TextStyle.paragraph,
        min_length=340,
        max_length=4000,
        required=True,
    )

    async def on_submit(self, interaction: discord.Interaction) -> None:
        if not await _check_owner_role_only(interaction):
            return

        user_id = interaction.user.id
        added_count = _start_bulk_session(user_id)
        remaining_slots = MAX_BULK_TOKEN_PAIRS - added_count
        pairs, validation_error = _prepare_bulk_token_pairs(
            str(self.bearer_tokens),
            str(self.refresh_tokens),
            remaining_slots,
        )
        if validation_error:
            await interaction.response.send_message(
                validation_error,
                ephemeral=True,
            )
            return

        try:
            total = _save_added_token_pairs(
                pairs,
                interaction.user,
                source="admin-bulk",
            )
        except OSError:
            await interaction.response.send_message(
                "❌ The token pairs could not be saved. Try again later.",
                ephemeral=True,
            )
            return

        added_count += len(pairs)
        _BULK_SESSIONS[user_id]["added_count"] = added_count
        remaining_slots = MAX_BULK_TOKEN_PAIRS - added_count
        if remaining_slots == 0:
            _BULK_SESSIONS.pop(user_id, None)
            await interaction.response.send_message(
                f"✅ Added **{len(pairs)}** token pair(s). The "
                f"**{MAX_BULK_TOKEN_PAIRS}**-pair bulk-add limit was reached. "
                f"Stored token pairs: **{total}**.",
                ephemeral=True,
            )
            return

        await interaction.response.send_message(
            f"✅ Added **{len(pairs)}** token pair(s). "
            f"This bulk-add session has **{added_count}/{MAX_BULK_TOKEN_PAIRS}** "
            f"pairs. You can add up to **{remaining_slots}** more.",
            view=MultipleTokenBatchView(user_id),
            ephemeral=True,
        )


class DonateTokenModal(AddTokenModal):
    async def on_submit(self, interaction: discord.Interaction) -> None:
        if not await _check_authorized_guild(interaction):
            return
        is_member, guild_id, membership_error = await _donation_server_member(
            interaction.user.id
        )
        if not is_member:
            await interaction.response.send_message(
                membership_error or "❌ Donation server membership is required.",
                ephemeral=True,
            )
            return

        await _store_submitted_token_pair(
            interaction,
            str(self.bearer_token),
            str(self.refresh_token),
            source="donation",
            source_guild_id=guild_id,
        )


class AddTokenButton(discord.ui.Button["TokenPanelView"]):
    def __init__(self) -> None:
        super().__init__(
            label="Add Token",
            style=discord.ButtonStyle.danger,
            emoji="➕",
            custom_id="token-panel:add-token",
            row=2,
        )

    async def callback(self, interaction: discord.Interaction) -> None:
        if not await _check_owner_only(interaction):
            return
        await interaction.response.send_modal(AddTokenModal())


class MultipleTokenBatchView(discord.ui.View):
    """Continuation controls for adding up to 49 pairs over several modals."""

    def __init__(self, owner_id: int) -> None:
        super().__init__(timeout=BULK_SESSION_TIMEOUT_SECONDS)
        self.owner_id = owner_id

    async def _check_button_owner(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.owner_id:
            await interaction.response.send_message(
                "❌ Only the owner who started this bulk-add session can use "
                "these controls.",
                ephemeral=True,
            )
            return False
        return await _check_owner_role_only(interaction)

    @discord.ui.button(
        label="Add More Tokens",
        style=discord.ButtonStyle.primary,
        emoji="➕",
    )
    async def add_more_tokens(
        self,
        interaction: discord.Interaction,
        _button: discord.ui.Button["MultipleTokenBatchView"],
    ) -> None:
        if not await self._check_button_owner(interaction):
            return
        added_count = _bulk_session_count(self.owner_id)
        remaining_slots = MAX_BULK_TOKEN_PAIRS - added_count
        if remaining_slots <= 0:
            _BULK_SESSIONS.pop(self.owner_id, None)
            await interaction.response.send_message(
                f"❌ This session already reached the "
                f"**{MAX_BULK_TOKEN_PAIRS}**-pair limit.",
                ephemeral=True,
            )
            return
        await interaction.response.send_modal(MultipleTokensModal())

    @discord.ui.button(
        label="Done",
        style=discord.ButtonStyle.secondary,
        emoji="✅",
    )
    async def finish_bulk_add(
        self,
        interaction: discord.Interaction,
        _button: discord.ui.Button["MultipleTokenBatchView"],
    ) -> None:
        if not await self._check_button_owner(interaction):
            return
        added_count = _bulk_session_count(self.owner_id)
        _BULK_SESSIONS.pop(self.owner_id, None)
        for child in self.children:
            child.disabled = True
        await interaction.response.edit_message(
            content=(
                f"✅ Bulk add finished with **{added_count}** token pair(s) "
                "added in this session."
            ),
            view=self,
        )


class MultipleTokensAddButton(discord.ui.Button["TokenPanelView"]):
    def __init__(self) -> None:
        super().__init__(
            label="Multiple Tokens Add",
            style=discord.ButtonStyle.danger,
            emoji="📚",
            custom_id="token-panel:multiple-tokens-add",
            row=2,
        )

    async def callback(self, interaction: discord.Interaction) -> None:
        if not await _check_owner_role_only(interaction):
            return
        added_count = _start_bulk_session(interaction.user.id)
        if added_count >= MAX_BULK_TOKEN_PAIRS:
            _BULK_SESSIONS.pop(interaction.user.id, None)
            await interaction.response.send_message(
                f"❌ A bulk-add session can contain at most "
                f"**{MAX_BULK_TOKEN_PAIRS}** token pairs.",
                ephemeral=True,
            )
            return
        await interaction.response.send_modal(MultipleTokensModal())


add_group = app_commands.Group(
    name="add",
    description="Administrator-only token management",
)
client.tree.add_command(add_group)


@add_group.command(
    name="token",
    description="Add a bearer token and refresh token",
)
async def add_token_command(interaction: discord.Interaction) -> None:
    if not await _check_admin_or_owner(interaction):
        return
    await interaction.response.send_modal(AddTokenModal())


donate_group = app_commands.Group(
    name="donate",
    description="Donate a token pair",
)
client.tree.add_command(donate_group)


@donate_group.command(
    name="token",
    description="Donate a non-expired bearer and refresh token",
)
async def donate_token_command(interaction: discord.Interaction) -> None:
    if not await _check_authorized_guild(interaction):
        return
    is_member, _, membership_error = await _donation_server_member(
        interaction.user.id
    )
    if not is_member:
        await interaction.response.send_message(
            membership_error or "❌ Donation server membership is required.",
            ephemeral=True,
        )
        return
    await interaction.response.send_modal(DonateTokenModal())


set_group = app_commands.Group(
    name="set",
    description="Configure the token panel",
)
client.tree.add_command(set_group)


@set_group.command(
    name="channel",
    description="Choose where the token generator panel should appear",
)
@app_commands.describe(channel="The text channel for the token generator panel")
async def set_channel_command(
    interaction: discord.Interaction,
    channel: discord.TextChannel,
) -> None:
    if not await _check_owner_or_co_owner(interaction):
        return
    if channel.guild.id != AUTHORIZED_GUILD_ID:
        await interaction.response.send_message(
            "❌ Choose a text channel from this authorized server.",
            ephemeral=True,
        )
        return

    await interaction.response.defer(ephemeral=True)
    try:
        _save_panel_channel_id(channel.id)
    except OSError:
        await interaction.followup.send(
            "❌ The channel setting could not be saved.",
            ephemeral=True,
        )
        return

    posted = await client._ensure_token_panel(channel_id=channel.id)
    if posted:
        await interaction.followup.send(
            f"✅ Token generator panel set to {channel.mention}.",
            ephemeral=True,
        )
    else:
        await interaction.followup.send(
            f"⚠️ Saved {channel.mention}, but I could not post the panel. "
            "Check my permissions in that channel.",
            ephemeral=True,
        )


delete_group = app_commands.Group(
    name="delete",
    description="Delete token data",
)
delete_all_group = app_commands.Group(
    name="all",
    description="Delete all token data",
)
delete_group.add_command(delete_all_group)
client.tree.add_command(delete_group)


@delete_all_group.command(
    name="tokens",
    description="Delete all token stock and issued token records",
)
async def delete_all_tokens_command(interaction: discord.Interaction) -> None:
    if not await _check_admin_or_owner(interaction):
        return

    try:
        stock_count, user_record_count = _delete_all_tokens()
    except OSError:
        await interaction.response.send_message(
            "❌ Some token files could not be deleted.",
            ephemeral=True,
        )
        return

    await interaction.response.send_message(
        "✅ All tokens deleted.\n"
        f"Removed **{stock_count}** token(s) from stock and "
        f"**{user_record_count}** issued token record(s).\n"
        "New generation attempts will say: "
        "**Out of stock. No valid tokens available in queue.**",
        ephemeral=True,
    )


rest_group = app_commands.Group(
    name="rest",
    description="Administrator-only reset actions",
)
cooldown_group = app_commands.Group(
    name="cooldown",
    description="Reset token cooldowns",
)
rest_group.add_command(cooldown_group)
client.tree.add_command(rest_group)


@cooldown_group.command(
    name="all",
    description="Reset everyone's token cooldown",
)
async def reset_all_cooldowns_command(
    interaction: discord.Interaction,
) -> None:
    if not await _check_admin_or_owner(interaction):
        return

    reset_count, skipped_count = _reset_all_cooldowns()
    message = (
        f"✅ Reset cooldowns for **{reset_count}** user(s). "
        "Their stored tokens were preserved."
    )
    if skipped_count:
        message += f"\n⚠️ Could not read **{skipped_count}** user file(s)."
    await interaction.response.send_message(message, ephemeral=True)


async def _check_token_access(
    interaction: discord.Interaction,
    token_type: str,
) -> bool:
    if not await _check_access(interaction):
        return False

    policy = _policy_for(token_type)
    role_id = int(policy["role_id"])
    if token_type != "public" and role_id == 0:
        await interaction.response.send_message(
            f"❌ The {policy['label']} button has not been configured yet.",
            ephemeral=True,
        )
        return False
    if role_id and not _has_role(interaction, role_id):
        await interaction.response.send_message(
            f"❌ You need the {_role_text(role_id)} role to use this button.",
            ephemeral=True,
        )
        return False
    return True


async def issue_token(
    interaction: discord.Interaction,
    token_type: str,
) -> None:
    if not await _check_token_access(interaction, token_type):
        return

    now = int(time.time())
    user_id = interaction.user.id
    stored = _load_user(user_id) or {}
    policy = _policy_for(token_type)
    cooldown_seconds = int(policy["cooldown_seconds"])
    existing_record = _stored_token_record(stored, token_type) or {}
    last_issued = int(existing_record.get("last_issued", 0))
    remaining_cooldown = max(0, cooldown_seconds - (now - last_issued))

    if remaining_cooldown:
        minutes, seconds = divmod(remaining_cooldown, 60)
        await interaction.response.send_message(
            f"⏳ **{policy['label']}** is on cooldown. "
            f"Next use in **{minutes}m {seconds}s**.",
            ephemeral=True,
        )
        return

    try:
        stock_pair = _take_stock_token_pair()
    except OSError:
        await interaction.response.send_message(
            "❌ Token stock could not be accessed. Try again later.",
            ephemeral=True,
        )
        return
    if stock_pair is None:
        await interaction.response.send_message(
            "Out of stock. No valid tokens available in queue.",
            ephemeral=True,
        )
        return

    expires_at = now + TOKEN_LIFETIME_SECONDS
    token, refresh_token = stock_pair
    expires_at = _jwt_expiry(token) or expires_at

    stored["user_id"] = str(user_id)
    stored["username"] = interaction.user.name
    stored.setdefault("tokens", {})
    stored["tokens"][token_type] = {
        "token": token,
        "refresh_token": refresh_token,
        "expires_at": expires_at,
        "last_issued": now,
        "cooldown_seconds": cooldown_seconds,
    }
    _save_user(user_id, stored)

    token_json = _make_response_json(
        token=token,
        refresh_token=refresh_token,
        expires_at=expires_at,
        next_use_in=cooldown_seconds,
    )
    await _send_token_bundle(interaction, token_json)


@client.tree.command(
    name="forgot-token",
    description="Re-send your current token JSON",
)
async def forgot_token_command(interaction: discord.Interaction) -> None:
    if not await _check_access(interaction):
        return

    stored = _load_user(interaction.user.id)
    public_record = (
        _stored_token_record(stored, "public") if stored else None
    )
    if (
        not public_record
        or not public_record.get("token")
        or _seconds_left(int(public_record.get("expires_at", 0))) == 0
    ):
        await interaction.response.send_message(
            "❌ You do not have an active public token. "
            "Use the Public Token button first.",
            ephemeral=True,
        )
        return

    token_json = _make_response_json(
        token=str(public_record["token"]),
        refresh_token=str(public_record["refresh_token"]),
        expires_at=int(public_record["expires_at"]),
        next_use_in=max(
            0,
            _cooldown_seconds_for(interaction)
            - (int(time.time()) - int(public_record.get("last_issued", 0))),
        ),
    )
    await _send_token_bundle(interaction, token_json)


@client.tree.command(
    name="delete-my-token",
    description="Delete your stored app token",
)
async def delete_my_token_command(interaction: discord.Interaction) -> None:
    if not await _check_access(interaction):
        return

    path = _user_file(interaction.user.id)
    if path.exists():
        path.unlink()
        await interaction.response.send_message(
            "✅ Your stored token was deleted.",
            ephemeral=True,
        )
    else:
        await interaction.response.send_message(
            "ℹ️ You do not have a stored token.",
            ephemeral=True,
        )


if __name__ == "__main__":
    if not DISCORD_BOT_TOKEN:
        raise RuntimeError("Set DISCORD_BOT_TOKEN before starting the bot.")
    if not TOKEN_SECRET or len(TOKEN_SECRET) < 32:
        raise RuntimeError(
            "Set TOKEN_SECRET to a random secret of at least 32 characters."
        )
    client.run(DISCORD_BOT_TOKEN)
