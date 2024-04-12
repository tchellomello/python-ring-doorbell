"""The tests for the Ring platform."""

import asyncio

import pytest
from ring_doorbell import Auth, Ring, RingError
from ring_doorbell.const import USER_AGENT

from .conftest import json_request_kwargs, load_fixture_as_dict, nojson_request_kwargs


def test_basic_attributes(ring):
    """Test the Ring class and methods."""
    data = ring.devices()
    assert len(data["chimes"]) == 1
    assert len(data["doorbots"]) == 1
    assert len(data["authorized_doorbots"]) == 1
    assert len(data["stickup_cams"]) == 1
    assert len(data["other"]) == 1


def test_chime_attributes(ring):
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

    assert len(dev.history()) == 0

    dev.update_health_data()
    assert dev.wifi_name == "ring_mock_wifi"
    assert dev.wifi_signal_category == "good"
    assert dev.wifi_signal_strength != 100


def test_doorbell_attributes(ring):
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

    assert isinstance(dev.history(limit=1, kind="motion"), list)
    assert len(dev.history(kind="ding")) == 1
    assert len(dev.history(limit=1, kind="motion")) == 2
    assert len(dev.history(limit=1, kind="motion", enforce_limit=True, retry=50)) == 1

    assert dev.existing_doorbell_type == "Mechanical"

    dev.update_health_data()

    assert dev.wifi_name == "ring_mock_wifi"
    assert dev.wifi_signal_category == "good"
    assert dev.wifi_signal_strength == -58


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

    kwargs = nojson_request_kwargs()

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


async def test_sync_queries_from_event_loop():
    auth = Auth(USER_AGENT, token=load_fixture_as_dict("ring_oauth.json"))
    ring = Ring(auth)

    loop = asyncio.get_running_loop()

    # This will run on the background thread
    ring.update_devices()
    assert auth._loop is not None
    assert auth._init_loop == loop
    assert auth._loop == auth._background_thread_loop

    auth.close()


async def test_sync_queries_from_executor():
    auth = Auth(USER_AGENT, token=load_fixture_as_dict("ring_oauth.json"))
    ring = Ring(auth)

    loop = asyncio.get_running_loop()
    assert auth._init_loop == loop

    # This will run the query on this loop
    await loop.run_in_executor(None, ring.update_devices)

    assert auth._loop == loop
    assert auth._loop != auth._background_thread_loop
    assert auth._loop == auth._init_loop
    await loop.run_in_executor(None, auth.close)


async def test_sync_queries_event_loop_change():
    auth = Auth(USER_AGENT, token=load_fixture_as_dict("ring_oauth.json"))

    ring = Ring(auth)
    loop = asyncio.get_running_loop()
    assert auth._loop is None

    await ring.async_update_devices()
    assert auth._loop == loop

    assert auth._background_thread_loop is None

    with pytest.raises(
        RingError, match="Detected event loop change, don't mix sync and async calls."
    ):
        ring.update_devices()

    await auth.async_close()


def test_sync_queries_with_no_event_loop():
    auth = Auth(USER_AGENT, token=load_fixture_as_dict("ring_oauth.json"))

    ring = Ring(auth)

    assert auth._loop is None

    ring.update_devices()

    assert auth._background_thread_loop is None

    auth.close()
