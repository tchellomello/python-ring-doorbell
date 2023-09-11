import json
import getpass
from pathlib import Path

from ring_doorbell import Ring, Auth
from oauthlib.oauth2 import MissingTokenError


cache_file = Path("test_token.cache")


def token_updated(token):
    cache_file.write_text(json.dumps(token))


def otp_callback():
    auth_code = input("2FA code: ")
    return auth_code


def main():
    if cache_file.is_file():
        auth = Auth("RingAPI2023/1.0", json.loads(cache_file.read_text()), token_updated)
    else:
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        auth = Auth("RingAPI2023/1.0", None, token_updated)
        try:
            auth.fetch_token(username, password)
        except MissingTokenError:
            auth.fetch_token(username, password, otp_callback())

    ring = Ring(auth)
    ring.update_data()

    devices = ring.devices()
    print(devices)

    doorbells = devices["doorbots"]
    chimes = devices["chimes"]
    stickup_cams = devices["stickup_cams"]

    print(doorbells)
    print(chimes)
    print(stickup_cams)


if __name__ == "__main__":
    main()
