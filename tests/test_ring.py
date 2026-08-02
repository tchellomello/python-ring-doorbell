"""The tests for the Ring platform."""

import asyncio
from datetime import datetime, timezone

import pytest
from freezegun.api import FrozenDateTimeFactory
from ring_doorbell import Auth, Ring, RingError
from ring_doorbell.const import MSG_EXISTING_TYPE, USER_AGENT
from ring_doorbell.util import parse_datetime

from .conftest import json_request_kwargs, load_fixture_as_dict


def test_basic_attributes(ring):
    """Test the Ring class and methods."""
    data = ring.devices()
    assert len(data["chimes"]) == 1
    assert len(data["doorbots"]) == 1
    assert len(data["authorized_doorbots"]) == 1
    assert len(data["stickup_cams"]) == 1
    assert len(data["other"]) == 1


async def test_chime_attributes(ring):
    """Test the Ring Chime class and methods."""
    dev = ring.devices()["chimes"][0]

    assert dev.address == "123 Main St"
    assert dev.id != 99999
    assert dev.device_id == "abcdef123"
    assert dev.kind == "chime"
    assert dev.model == "Chime"
    assert dev.has_capability("battery") is False
    assert dev.has_capability("volume") is True
    assert dev.has_capability("history") is False
    assert dev.latitude is not None
    assert dev.timezone == "America/New_York"
    assert dev.volume == 2

    assert len(await dev.async_history()) == 0

    await dev.async_update_health_data()
    assert dev.wifi_name == "ring_mock_wifi"
    assert dev.wifi_signal_category == "good"
    assert dev.wifi_signal_strength != 100


async def test_doorbell_attributes(ring):
    data = ring.devices()
    dev = data["doorbots"][0]
    assert dev.name == "Front Door"
    assert dev.id == 987652
    assert dev.address == "123 Main St"
    assert dev.kind == "lpd_v1"
    assert dev.model == "Doorbell Pro"
    assert dev.has_capability("battery") is False
    assert dev.has_capability("volume") is True
    assert dev.has_capability("history") is True
    assert dev.longitude == -70.12345
    assert dev.timezone == "America/New_York"
    assert dev.volume == 1
    assert dev.has_subscription is True
    assert dev.connection_status == "online"

    assert isinstance(await dev.async_history(limit=1, kind="motion"), list)
    assert len(await dev.async_history(kind="ding")) == 1
    assert len(await dev.async_history(limit=1, kind="motion")) == 2
    assert (
        len(
            await dev.async_history(
                limit=1, kind="motion", enforce_limit=True, retry=50
            )
        )
        == 1
    )

    assert dev.existing_doorbell_type == "Mechanical"

    await dev.async_update_health_data()

    assert dev.wifi_name == "ring_mock_wifi"
    assert dev.wifi_signal_category == "good"
    assert dev.wifi_signal_strength == -58


def test_wired_doorbell_plus_2_attributes(ring):
    dev = ring.devices()["doorbots"][0]
    dev._attrs["kind"] = "cocoa_doorbell_v4w"
    dev._attrs["battery_life"] = None
    dev._attrs["external_connection"] = True
    dev._attrs["health"] = {"ac_power": 1}
    dev._attrs["settings"]["preroll_enabled"] = True
    dev._attrs["settings"]["power_mode"] = "wired"

    assert dev.model == "Wired Doorbell Plus (2nd Gen)"
    assert dev.battery_life is None
    assert dev.has_capability("battery") is False
    assert dev.has_capability("ding") is True
    assert dev.has_capability("history") is True
    assert dev.has_capability("knock") is False
    assert dev.has_capability("motion_detection") is True
    assert dev.has_capability("pre_roll") is True
    assert dev.has_capability("video") is True
    assert dev.has_capability("volume") is True


def test_shared_doorbell_attributes(ring):
    data = ring.devices()
    dev = data["authorized_doorbots"][0]

    assert dev.id == 987653
    assert dev.battery_life == 51
    assert dev.address == "123 Second St"
    assert dev.kind == "lpd_v1"
    assert dev.model == "Doorbell Pro"
    assert dev.has_capability("battery") is False
    assert dev.has_capability("volume") is True
    assert dev.has_capability("history") is True
    assert dev.longitude == -70.12345
    assert dev.timezone == "America/New_York"
    assert dev.volume == 5
    assert dev.existing_doorbell_type == "Digital"


def test_stickup_cam_attributes(ring):
    dev = ring.devices()["stickup_cams"][0]
    assert dev.kind == "hp_cam_v1"
    assert dev.model == "Floodlight Cam"
    assert dev.has_capability("battery") is False
    assert dev.has_capability("light") is True
    assert dev.has_capability("history") is True
    assert dev.lights == "off"
    assert dev.siren == 0


async def test_stickup_cam_controls(ring, aioresponses_mock):
    dev = ring.devices()["stickup_cams"][0]

    kwargs = json_request_kwargs()
    kwargs["json"] = None

    await dev.async_set_lights("off")
    aioresponses_mock.assert_called_with(
        url="https://api.ring.com/clients_api/doorbots/987652/floodlight_light_off",
        method="PUT",
        **kwargs,
    )
    await dev.async_set_lights("on")
    aioresponses_mock.assert_called_with(
        url="https://api.ring.com/clients_api/doorbots/987652/floodlight_light_on",
        method="PUT",
        **kwargs,
    )
    await dev.async_set_siren(0)
    aioresponses_mock.assert_called_with(
        url="https://api.ring.com/clients_api/doorbots/987652/siren_off",
        method="PUT",
        **kwargs,
    )
    await dev.async_set_siren(30)
    kwargs["params"] = {"duration": 30}
    aioresponses_mock.assert_called_with(
        url="https://api.ring.com/clients_api/doorbots/987652/siren_on",
        method="PUT",
        **kwargs,
    )


async def test_light_groups(ring):
    group = ring.groups()["mock-group-id"]

    assert group.name == "Landscape"
    assert group.family == "group"
    assert group.group_id == "mock-group-id"
    assert group.location_id == "mock-location-id"
    assert group.model == "Light Group"
    assert group.has_capability("light") is True
    with pytest.raises(RingError):
        group.has_capability("something-else")

    with pytest.raises(
        RingError,
        match=(
            "You need to call update on the group before "
            "accessing the lights property."
        ),
    ):
        assert group.lights is False
    await group.async_update()

    # Attempt turning on lights
    await group.async_set_lights(state=True)

    # Attempt turning off lights
    await group.async_set_lights(state=False)

    # Attempt turning on lights for 30 seconds
    await group.async_set_lights(state=True, duration=30)


async def test_motion_detection_enable(ring, aioresponses_mock):
    dev = ring.devices()["doorbots"][0]

    kwargs = json_request_kwargs()
    await dev.async_set_motion_detection(state=True)
    kwargs["json"] = {"motion_settings": {"motion_detection_enabled": True}}
    aioresponses_mock.assert_called_with(
        url="https://api.ring.com/devices/v1/devices/987652/settings",
        method="PATCH",
        **kwargs,
    )

    await dev.async_set_motion_detection(state=False)

    kwargs["json"] = {"motion_settings": {"motion_detection_enabled": False}}
    aioresponses_mock.assert_called_with(
        url="https://api.ring.com/devices/v1/devices/987652/settings",
        method="PATCH",
        **kwargs,
    )


@pytest.mark.parametrize(
    ("datetime_string", "expected", "error_in_log"),
    [
        pytest.param(
            "2012-01-15T06:01:01",
            datetime(2012, 1, 14, 5, 5, 5, 123 * 1_000, tzinfo=timezone.utc),
            True,
            id="No timezone",
        ),
        pytest.param(
            "2012-01-15T06:01:01.12Z",
            datetime(2012, 1, 15, 6, 1, 1, 120 * 1_000, tzinfo=timezone.utc),
            False,
            id="Millis",
        ),
        pytest.param(
            "2012-01-15T06:01:01.123456Z",
            datetime(2012, 1, 15, 6, 1, 1, 123456, tzinfo=timezone.utc),
            False,
            id="Micros",
        ),
        pytest.param(
            "2012-01-15T06:01:01Z",
            datetime(2012, 1, 15, 6, 1, 1, 0, tzinfo=timezone.utc),
            False,
            id="No millis",
        ),
    ],
)
def test_datetime_parse(
    freezer: FrozenDateTimeFactory,
    caplog: pytest.LogCaptureFixture,
    datetime_string,
    expected,
    error_in_log,
):
    """Test the datetime parsing."""
    freezer.move_to("2012-01-14T05:05:05.123Z")
    dt = parse_datetime(datetime_string)
    is_error_in_log = (
        f"Unable to parse datetime string {datetime_string}, defaulting to now time"
        in caplog.text
    )
    assert dt == expected
    assert is_error_in_log is error_in_log


async def test_sync_queries_from_event_loop():
    auth = Auth(USER_AGENT, token=load_fixture_as_dict("ring_oauth.json"))
    ring = Ring(auth)

    assert asyncio.get_running_loop()

    msg = (
        "You cannot call deprecated sync function Ring.update_devices "
        "from within a running event loop."
    )
    with pytest.raises(RingError, match=msg):
        ring.update_devices()


async def test_sync_queries_from_executor():
    auth = Auth(USER_AGENT, token=load_fixture_as_dict("ring_oauth.json"))
    ring = Ring(auth)

    loop = asyncio.get_running_loop()

    assert ring.devices_data == {}
    # This will run the query inan executor thread
    msg = "Ring.update_devices is deprecated, use Ring.async_update_devices"
    with pytest.deprecated_call(match=msg):
        await loop.run_in_executor(None, ring.update_devices)

    assert ring.devices_data


def test_sync_queries_with_no_event_loop():
    auth = Auth(USER_AGENT, token=load_fixture_as_dict("ring_oauth.json"))

    ring = Ring(auth)

    assert not ring.devices_data
    msg = "Ring.update_devices is deprecated, use Ring.async_update_devices"
    with pytest.deprecated_call(match=msg):
        ring.update_devices()

    assert ring.devices_data

    with pytest.deprecated_call():
        auth.close()


async def test_set_existing_doorbell_type(ring, aioresponses_mock):
    data = ring.devices()
    dev = data["doorbots"][0]
    assert dev.existing_doorbell_type == "Mechanical"

    kwargs = json_request_kwargs()
    kwargs["json"] = None

    aioresponses_mock.requests.clear()
    # Attempting to turn off the in-home chime
    await dev.async_set_existing_doorbell_type_enabled(value=False)
    kwargs["params"] = {
        "doorbot[description]": dev.name,
        "doorbot[settings][chime_settings][enable]": 0,
    }
    aioresponses_mock.assert_called_with(
        url="https://api.ring.com/clients_api/doorbots/987652",
        method="PUT",
        **kwargs,
    )

    aioresponses_mock.requests.clear()
    # Attempting to turn on the in-home chime
    await dev.async_set_existing_doorbell_type_enabled(value=True)
    kwargs["params"] = {
        "doorbot[description]": dev.name,
        "doorbot[settings][chime_settings][enable]": 1,
    }
    aioresponses_mock.assert_called_with(
        url="https://api.ring.com/clients_api/doorbots/987652",
        method="PUT",
        **kwargs,
    )

    aioresponses_mock.requests.clear()
    # Attempting to set the doorbell type
    await dev.async_set_existing_doorbell_type(2)
    kwargs["params"] = {
        "doorbot[description]": dev.name,
        "doorbot[settings][chime_settings][type]": 2,
    }
    aioresponses_mock.assert_called_with(
        url="https://api.ring.com/clients_api/doorbots/987652",
        method="PUT",
        **kwargs,
    )

    aioresponses_mock.requests.clear()
    # Attempting to set the duration of the in-home chime
    settings = dev._attrs["settings"]["chime_settings"]
    settings["type"] = 1
    assert dev.existing_doorbell_type == "Digital"
    await dev.async_set_existing_doorbell_type_duration(5)
    kwargs["params"] = {
        "doorbot[description]": dev.name,
        "doorbot[settings][chime_settings][duration]": 5,
    }
    aioresponses_mock.assert_called_with(
        url="https://api.ring.com/clients_api/doorbots/987652",
        method="PUT",
        **kwargs,
    )

    # Attempting to enable when no chime present
    settings = dev._attrs["settings"]["chime_settings"]
    settings["type"] = 2
    assert dev.existing_doorbell_type == "Not Present"

    with pytest.raises(RingError, match="In-Home chime is not present."):
        await dev.async_set_existing_doorbell_type_enabled(value=True)

    # Attempting to set the doorbell type to an invalid value
    with pytest.raises(RingError, match=f"value must be in {MSG_EXISTING_TYPE}"):
        await dev.async_set_existing_doorbell_type(4)

    # Attempting to set the doorbell duration to an invalid value
    with pytest.raises(RingError, match=f"Must be within the {0}-{1}."):
        await dev.async_set_existing_doorbell_type_duration(11)
