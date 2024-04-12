"""Test module which runs the first example in the README."""

import getpass
import json
from pathlib import Path

from ring_doorbell import Auth, AuthenticationError, Requires2FAError, Ring

user_agent = "YourProjectName-1.0"  # Change this
cache_file = Path(user_agent + ".token.cache")


def token_updated(token) -> None:
    cache_file.write_text(json.dumps(token))


def otp_callback():
    return input("2FA code: ")


def do_auth():
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    auth = Auth(user_agent, None, token_updated)
    try:
        auth.fetch_token(username, password)
    except Requires2FAError:
        auth.fetch_token(username, password, otp_callback())
    return auth


def main() -> None:
    if cache_file.is_file():  # auth token is cached
        auth = Auth(user_agent, json.loads(cache_file.read_text()), token_updated)
        ring = Ring(auth)
        try:
            ring.create_session()  # auth token still valid
        except AuthenticationError:  # auth token has expired
            auth = do_auth()
    else:
        auth = do_auth()  # Get new auth token
        ring = Ring(auth)

    ring.update_data()

    print(ring.devices())


if __name__ == "__main__":
    main()