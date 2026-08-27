import os
import json
import random
import discord
from discord.ext import commands

BOT_TOKEN = os.getenv("BOT_TOKEN")

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN environment variable is missing")

BASE_FOLDER = os.path.dirname(os.path.abspath(__file__))
FOLDER = os.path.join(BASE_FOLDER, "files")


class Bot(commands.Bot):
    def __init__(self):
        super().__init__(
            command_prefix="!",
            intents=discord.Intents.default()
        )

    async def setup_hook(self):
        await self.tree.sync()


bot = Bot()


@bot.event
async def on_ready():
    print(f"Online: {bot.user}")
    os.makedirs(FOLDER, exist_ok=True)


@bot.tree.command(
    name="generate_token",
    description="Fetch an AC token"
)
async def generate_token(
    interaction: discord.Interaction
):
    await interaction.response.defer(ephemeral=True)

    try:
        files = [
            os.path.join(FOLDER, name)
            for name in os.listdir(FOLDER)
            if os.path.isfile(os.path.join(FOLDER, name))
            and name.lower().endswith(".json")
        ]

        if not files:
            await interaction.followup.send(
                "❌ No JSON tokens available.",
                ephemeral=True
            )
            return

        chosen_file = random.choice(files)

        await interaction.followup.send(
            file=discord.File(chosen_file),
            ephemeral=True
        )

        os.remove(chosen_file)

        print(f"Sent and deleted: {chosen_file}")

    except Exception as e:
        print("GENERATE ERROR:", repr(e))

        await interaction.followup.send(
            f"❌ Error: `{e}`",
            ephemeral=True
        )


@bot.tree.command(
    name="status",
    description="Show token system status"
)
async def status(
    interaction: discord.Interaction
):
    await interaction.response.defer(ephemeral=True)

    try:
        os.makedirs(FOLDER, exist_ok=True)

        file_count = sum(
            os.path.isfile(
                os.path.join(FOLDER, name)
            )
            for name in os.listdir(FOLDER)
        )

        result = {
            "public_pool": {
                "status": (
                    "available"
                    if file_count > 0
                    else "empty"
                ),
                "files": file_count
            }
        }

        await interaction.followup.send(
            "📊 **System Status**\n"
            f"```json\n"
            f"{json.dumps(result, indent=2)}\n"
            f"```",
            ephemeral=True
        )

    except Exception as e:
        print("STATUS ERROR:", repr(e))

        await interaction.followup.send(
            f"❌ Status failed: `{e}`",
            ephemeral=True
        )


bot.run(BOT_TOKEN)
