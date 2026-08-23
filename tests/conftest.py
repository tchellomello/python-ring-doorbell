"""Test configuration for the Ring platform."""

from __future__ import annotations

import datetime
import json
import re
from pathlib import Path
from time import time
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
from aiointercept import CallbackResult, aiointercept
from ring_doorbell import Auth, Ring
from ring_doorbell.const import USER_AGENT

if TYPE_CHECKING:
    from collections.abc import Generator


# The kwargs below are useful for request assertions
def json_request_kwargs():
    return {
        "headers": {
            "User-Agent": "android:com.ringapp",
            "hardware_id": "21ac3af1-0eac-5fbd-8b0f-0b784889bfbd",
            "Content-Type": "application/json",
            "Authorization": "Bearer dummyBearerToken",
        },
        "data": None,
        "params": {},
        "json": {},
    }


def nojson_request_kwargs():
    return {
        "headers": {
            "User-Agent": "android:com.ringapp",
            "hardware_id": "21ac3af1-0eac-5fbd-8b0f-0b784889bfbd",
            "Authorization": "Bearer dummyBearerToken",
        },
        "data": None,
        "params": {},
    }


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "nolistenmock: mark test to not want the autouse listenmock"
    )


@pytest.fixture
async def auth():
    """Return auth object."""
    auth = Auth(USER_AGENT)
    await auth.async_fetch_token("foo", "bar")
    yield auth

    await auth.async_close()


@pytest.fixture
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


def load_alert_v1(
    alert_type: str, device_id, *, ding_id_inc: int = 0, created_at: str | None = None
) -> dict:
    msg = json.loads(load_fixture(Path().joinpath("listen", "fcmdata_v1.json")))
    gcmdata = json.loads(
        load_fixture(Path().joinpath("listen", f"{alert_type}_gcmdata.json"))
    )
    if created_at is None:
        created_at = datetime.datetime.utcnow().isoformat(timespec="milliseconds") + "Z"  # noqa: DTZ003
    if "ding" in gcmdata:
        gcmdata["ding"]["doorbot_id"] = device_id
        gcmdata["ding"]["created_at"] = created_at
        gcmdata["ding"]["id"] = gcmdata["ding"]["id"] + ding_id_inc
    else:
        gcmdata["alarm_meta"]["device_zid"] = device_id
    msg["data"]["gcmData"] = json.dumps(gcmdata)
    return msg


def load_alert_v2(
    alert_type: str, device_id, *, ding_id_inc: int = 0, created_at: str | None = None
) -> dict:
    msg = json.loads(load_fixture(Path().joinpath("listen", "fcmdata_v2.json")))
    data = json.loads(
        load_fixture(Path().joinpath("listen", f"{alert_type}_data.json"))
    )
    android_config = json.loads(
        load_fixture(Path().joinpath("listen", f"{alert_type}_android_config.json"))
    )
    analytics = json.loads(
        load_fixture(Path().joinpath("listen", f"{alert_type}_analytics.json"))
    )
    if created_at is None:
        created_at = datetime.datetime.utcnow().isoformat(timespec="milliseconds") + "Z"  # noqa: DTZ003
    data["device"]["id"] = device_id
    data["event"]["ding"]["created_at"] = created_at
    data["event"]["ding"]["id"] = str(int(data["event"]["ding"]["id"]) + ding_id_inc)
    msg["data"]["data"] = json.dumps(data)
    msg["data"]["android_config"] = json.dumps(android_config)
    msg["data"]["analytics"] = json.dumps(analytics)
    return msg


@pytest.fixture(autouse=True)
def _listen_mock(mocker, request) -> None:
    if "nolistenmock" in request.keywords:
        return

    mocker.patch(
        "firebase_messaging.FcmPushClient.checkin_or_register", return_value="foobar"
    )
    mocker.patch("firebase_messaging.FcmPushClient.start")
    mocker.patch("firebase_messaging.FcmPushClient.stop")
    mocker.patch("firebase_messaging.FcmPushClient.is_started", return_value=True)


def callback(url, **kwargs):  # noqa: ANN003
    return CallbackResult(status=418)


# tests to pull in request_mock and append uris
@pytest.fixture
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


@pytest.fixture
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


@pytest.fixture(autouse=True, name="hardware_id_mock")
def _hardware_id_mock_fixture() -> Generator:
    """Fixture to patch getnode ensures all tests generate same hardware_id."""
    with patch("uuid.getnode", return_value=12345678901):
        yield


# setting the fixture name allows other tests to pull in the mock and append uris
@pytest.fixture(autouse=True, name="aiointercept_mock")
async def aiointercept_mock_fixture(request, devices_fixture, putpatch_status_fixture):
    async with aiointercept(mock_external_urls=True) as mock:
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
