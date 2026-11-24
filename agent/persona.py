from __future__ import annotations

import random

LINES = {
    "ignore": [
        "Regular. Let 'em in.",
        "Nothing to see. Enjoy the juice.",
        "Looks like a customer to me.",
    ],
    "ignore_probe": [
        "Looking for WordPress? Wrong club, pal.",
        "Knocking on doors this place doesn't have. Cute.",
        "That's a PHP door. We don't do PHP here.",
        "Scanner shuffling past. Not worth getting up for.",
    ],
    "watch": [
        "Something's off. I've got my eye on you.",
        "Hm. Noted. Keep walking.",
        "Not trouble yet. Yet.",
    ],
    "tarpit": [
        "Slow lane for you. Take a number.",
        "Sure, wait right here. For a while.",
        "We're very busy tonight. Very, very busy.",
    ],
    "replay": [
        "Let's see if that trick actually works. Back room, please.",
        "Bold move. Trying it on the stunt double first.",
        "Hold that thought. Testing your little key in the practice lock.",
    ],
    "block": [
        "You're done. Out.",
        "Not on the list. Not tonight.",
        "Door's closed for you. Fifteen minutes, then we'll talk.",
    ],
    "proven": [
        "It worked on the stunt double. That's a real hole. Calling the carpenter.",
        "Confirmed: that one gets in. Bouncing them, patching the wall.",
    ],
    "not_reproduced": [
        "All talk. Tried it in the back room, nothing happened.",
        "Fake ID. Didn't work on the practice lock.",
    ],
    "inconclusive": [
        "Can't tell from one try. Keeping them on a short leash.",
    ],
    "minor": [
        "Made the bartender drop a glass. Embarrassing, not dangerous.",
    ],
    "honeypot": [
        "Took the fake keys off the counter. Classic. I wrote down the face.",
        "Grabbed the .env. Every keychain in there is a tripwire.",
    ],
    "canary_reuse": [
        "There it is. The fake keys from the counter, tried on the front door. Gotcha.",
        "Same keys I left out as bait. Out you go.",
    ],
}


def line(kind: str, rng: random.Random | None = None) -> str:
    options = LINES.get(kind) or LINES["watch"]
    return (rng or random).choice(options)


def shame_caption(path: str, count: int) -> str:
    bare = path.split("?", 1)[0]
    if "wp-" in bare or bare.endswith(".php"):
        return f"{count}x tried to log into WordPress. This is a juice shop."
    if ".git" in bare:
        return f"{count}x asked for our git history. Bold."
    if ".env" in bare:
        return f"{count}x went straight for the secrets drawer."
    if "admin" in bare:
        return f"{count}x looking for the manager."
    return f"{count}x knocked on {bare}"
