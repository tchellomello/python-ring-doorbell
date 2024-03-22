"""Test configuration for the Ring platform."""

import json
import re
from pathlib import Path
from time import time

import pytest
from aioresponses import CallbackResult, aioresponses
from ring_doorbell import Auth, Ring
from ring_doorbell.const import USER_AGENT
from ring_doorbell.listen import can_listen


# The kwargs below are useful for request assertions
def json_request_kwargs():
    return {
        "headers": {
            "User-Agent": "android:com.ringapp",
            "Content-Type": "application/json",
            "Authorization": "Bearer dummyBearerToken",
        },
        "timeout": 10,
        "data": None,
        "params": {},
        "json": {},
    }


def nojson_request_kwargs():
    return {
        "headers": {
            "User-Agent": "android:com.ringapp",
            "Authorization": "Bearer dummyBearerToken",
        },
        "timeout": 10,
        "data": None,
        "params": {},
    }


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "nolistenmock: mark test to not want the autouse listenmock"
    )


@pytest.fixture()
async def auth():
    """Return auth object."""
    auth = Auth(USER_AGENT)
    await auth.async_fetch_token("foo", "bar")
    yield auth

    await auth.async_close()


@pytest.fixture()
async def ring(auth):
    """Return updated ring object."""
    ring = Ring(auth)
    await ring.async_update_data()
    return ring


def _set_dings_to_now(active_dings) -> None:
    for ding in active_dings:
        ding["now"] = time()

    return active_dings


def load_fixture(filename):
    """Load a fixture."""
    path = Path(Path(__file__).parent / "fixtures" / filename)
    with path.open() as fdp:
        return fdp.read()


def load_fixture_as_dict(filename):
    """Load a fixture."""
    return json.loads(load_fixture(filename))


@pytest.fixture(autouse=True)
def _listen_mock(mocker, request) -> None:
    if not can_listen or "nolistenmock" in request.keywords:
        return

    mocker.patch("firebase_messaging.FcmPushClient.checkin", return_value="foobar")
    mocker.patch("firebase_messaging.FcmPushClient.start")
    mocker.patch("firebase_messaging.FcmPushClient.is_started", return_value=True)


def callback(url, **kwargs):  # noqa: ANN003
    return CallbackResult(status=418)


# tests to pull in request_mock and append uris
@pytest.fixture()
def devices_fixture():
    class Devices:
        def __init__(self) -> None:
            """Initialise the class."""
            self.updated = False

        def devices(self) -> dict:
            """Get the devices."""
            if not self.updated:
                return load_fixture_as_dict("ring_devices.json")
            return load_fixture_as_dict("ring_devices_updated.json")

        def callback(self, url, **kwargs) -> CallbackResult:  # noqa: ARG002, ANN003
            """Return the callback result."""
            return CallbackResult(payload=self.devices())

    return Devices()


@pytest.fixture()
def putpatch_status_fixture():
    class StatusOverrides:
        def __init__(self) -> None:
            """Initialise the class."""
            self.overrides = {}

        def callback(self, url, **kwargs) -> CallbackResult:  # noqa: ANN003, ARG002
            """Return the callback."""
            plain_url = str(url)
            if plain_url in self.overrides:
                return CallbackResult(body=b"", status=self.overrides[plain_url])

            return CallbackResult(body=b"", status=204)

    return StatusOverrides()


# setting the fixture name to requests_mock allows other
# tests to pull in request_mock and append uris
@pytest.fixture(autouse=True, name="aioresponses_mock")
def aioresponses_mock_fixture(request, devices_fixture, putpatch_status_fixture):
    with aioresponses() as mock:
        mock.post(
            "https://oauth.ring.com/oauth/token",
            payload=load_fixture_as_dict("ring_oauth.json"),
            repeat=True,
        )
        mock.post(
            "https://api.ring.com/clients_api/session",
            payload=load_fixture_as_dict("ring_session.json"),
            repeat=True,
        )
        mock.get(
            "https://api.ring.com/clients_api/ring_devices",
            callback=devices_fixture.callback,
            repeat=True,
        )
        mock.get(
            re.compile(r"https:\/\/api\.ring\.com\/clients_api\/chimes\/\d+\/health"),
            payload=load_fixture_as_dict("ring_chime_health_attrs.json"),
            repeat=True,
        )
        mock.get(
            re.compile(r"https:\/\/api\.ring\.com\/clients_api\/doorbots\/\d+\/health"),
            payload=load_fixture_as_dict("ring_doorboot_health_attrs.json"),
            repeat=True,
        )
        mock.get(
            re.compile(
                r"https:\/\/api\.ring\.com\/clients_api\/doorbots\/185036587\/history.*$"
            ),
            payload=load_fixture_as_dict("ring_intercom_history.json"),
            repeat=True,
        )
        mock.get(
            re.compile(
                r"https:\/\/api\.ring\.com\/clients_api\/doorbots\/\d+\/history.*$"
            ),
            payload=load_fixture_as_dict("ring_doorbot_history.json"),
            repeat=True,
        )
        mock.get(
            "https://api.ring.com/clients_api/dings/active",
            payload=_set_dings_to_now(load_fixture_as_dict("ring_ding_active.json")),
            repeat=True,
        )
        mock.put(
            "https://api.ring.com/clients_api/doorbots/987652/floodlight_light_off",
            payload="ok",
            repeat=True,
        )
        mock.put(
            "https://api.ring.com/clients_api/doorbots/987652/floodlight_light_on",
            payload="ok",
            repeat=True,
        )
        mock.put(
            "https://api.ring.com/clients_api/doorbots/987652/siren_on",
            payload="ok",
            repeat=True,
        )
        mock.put(
            "https://api.ring.com/clients_api/doorbots/987652/siren_off",
            payload="ok",
            repeat=True,
        )
        mock.get(
            "https://api.ring.com/groups/v1/locations/mock-location-id/groups",
            payload=load_fixture_as_dict("ring_groups.json"),
            repeat=True,
        )
        mock.get(
            "https://api.ring.com/groups/v1/locations/"
            "mock-location-id/groups/mock-group-id/devices",
            payload=load_fixture_as_dict("ring_group_devices.json"),
            repeat=True,
        )
        mock.post(
            "https://api.ring.com/groups/v1/locations/"
            "mock-location-id/groups/mock-group-id/devices",
            payload="ok",
            repeat=True,
        )
        mock.patch(
            re.compile(
                r"https:\/\/api\.ring\.com\/devices\/v1\/devices\/\d+\/settings"
            ),
            payload="ok",
            repeat=True,
        )
        mock.get(
            re.compile(r"https:\/\/api\.ring\.com\/clients_api\/dings\/\d+\/recording"),
            status=200,
            body=b"123456",
            repeat=True,
        )
        mock.get(
            "https://api.ring.com/clients_api/dings/9876543212/recording",
            status=200,
            body=b"123456",
            repeat=True,
        )
        mock.patch(
            "https://api.ring.com/clients_api/device",
            callback=putpatch_status_fixture.callback,
            repeat=True,
        )
        mock.put(
            re.compile(r"https:\/\/api\.ring\.com\/clients_api\/doorbots\/.*$"),
            status=204,
            body=b"",
            repeat=True,
        )
        mock.get(
            "https://api.ring.com/devices/v1/devices/185036587/settings",
            payload=load_fixture_as_dict("ring_intercom_settings.json"),
            repeat=True,
        )
        mock.get(
            "https://api.ring.com/clients_api/locations/mock-location-id/users",
            payload=load_fixture_as_dict("ring_intercom_users.json"),
            repeat=True,
        )
        mock.post(
            "https://api.ring.com/clients_api/locations/mock-location-id/invitations",
            payload="ok",
            repeat=True,
        )
        mock.delete(
            (
                "https://api.ring.com/clients_api/locations/"
                "mock-location-id/invitations/123456789"
            ),
            payload="ok",
            repeat=True,
        )
        requestid = "44529542-3ed7-41da-807e-c170a01bac1d"
        mock.put(
            "https://api.ring.com/commands/v1/devices/185036587/device_rpc",
            body=(
                '{"result": {"code": 0}, "id": "' + requestid + '", "jsonrpc": "2.0"}'
            ).encode(),
            repeat=True,
        )
        yield mock
