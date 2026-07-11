APP_NAME = "M0X1 SOC Platform"
VERSION = "v0.1 Alpha"
AUTHOR = "M0X1"

THEME_COLOR = "cyan"
STATUS = "READY"


import os
from getpass import getpass

from dotenv import find_dotenv, load_dotenv, set_key

# --------------------------------------------------------------------------
# Locate (or create) the .env file that stores VT_API_KEY.
# find_dotenv() walks up from the current working directory looking for an
# existing .env file. If none exists yet, we create one next to config.py
# so future runs always find the same file.
# --------------------------------------------------------------------------
ENV_PATH = find_dotenv()
if not ENV_PATH:
    ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    open(ENV_PATH, "a", encoding="utf-8").close()

load_dotenv(ENV_PATH)


def _prompt_and_save_key(prompt_text: str) -> str:
    """
    Prompt the user for a VirusTotal API key (hidden input via getpass),
    persist it into the .env file, and reload the environment so the new
    value is immediately available via os.getenv().

    Args:
        prompt_text (str): The text shown to the user at the prompt.

    Returns:
        str: The newly entered API key.
    """
    api_key = getpass(prompt_text).strip()

    while not api_key:
        api_key = getpass(f"API key cannot be empty. {prompt_text}").strip()

    # Create/update (overwrite) the .env file with the new key.
    set_key(ENV_PATH, "VT_API_KEY", api_key)

    # Reload environment so os.getenv reflects the newly saved key.
    load_dotenv(ENV_PATH, override=True)
    os.environ["VT_API_KEY"] = api_key

    return api_key


def get_vt_api_key() -> str:
    """
    Retrieve the VirusTotal API key.

    Behavior:
        1. Try to load VT_API_KEY from the .env file / environment.
        2. If it exists, return it immediately.
        3. If it does not exist:
            - Prompt the user in the terminal (input hidden via getpass).
            - Persist the key into the .env file as VT_API_KEY=<key>.
            - Reload the environment so the new value is available.
            - Return the key.

    Returns:
        str: The VirusTotal API key.
    """
    api_key = os.getenv("VT_API_KEY")

    if api_key:
        return api_key

    print("\n[Config] No VirusTotal API key found in .env.")
    api_key = _prompt_and_save_key("Enter your VirusTotal API key: ")
    print("[Config] API key saved to .env. It will be used automatically next time.\n")

    return api_key


def prompt_new_vt_api_key() -> str:
    """
    Force-prompt the user for a NEW VirusTotal API key, overwriting whatever
    is currently stored in the .env file. Used when a previously saved key
    turns out to be invalid/rejected (HTTP 401) so the user never has to
    open or edit the .env file by hand.

    Returns:
        str: The newly entered and saved API key.
    """
    print("\n[Config] Please enter a new VirusTotal API key.")
    api_key = _prompt_and_save_key("New VirusTotal API key: ")
    print("[Config] New API key saved to .env.\n")

    return api_key


# --------------------------------------------------------------------------
# NOTE: get_vt_api_key() is intentionally NOT called here at import time.
# Importing config.py must never trigger a terminal prompt. Modules that
# actually need the VirusTotal API key (e.g. threat_intelligence.py) should
# call get_vt_api_key() lazily, right before they make a VirusTotal request.
# --------------------------------------------------------------------------