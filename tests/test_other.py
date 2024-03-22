"""The tests for the Ring platform."""

from .conftest import json_request_kwargs, nojson_request_kwargs


async def test_other_attributes(ring):
    """Test the Ring Other class and methods."""
    dev = ring.devices()["other"][0]

    assert dev.id != 99999
    assert dev.device_id == "124ba1b3fe1a"
    assert dev.kind == "intercom_handset_audio"
    assert dev.model == "Intercom"
    assert dev.location_id == "mock-location-id"
    assert dev.has_capability("battery") is False
    assert dev.has_capability("open") is True
    assert dev.has_capability("history") is True
    assert dev.timezone == "Europe/Rome"
    assert dev.battery_life == 52
    assert dev.doorbell_volume == 8
    assert dev.mic_volume == 11
    assert await dev.async_clip_length_max() == 60
    assert dev.connection_status == "online"
    assert len(await dev.async_allowed_users()) == 2
    assert dev.subscribed is True
    assert dev.has_subscription is True
    assert dev.unlock_duration is None
    assert dev.keep_alive_auto == 45.0

    assert isinstance(await dev.async_history(limit=1, kind="on_demand"), list)
    assert len(await dev.async_history(kind="ding")) == 1
    assert len(await dev.async_history(limit=1, kind="on_demand")) == 2
    assert (
        len(
            await dev.async_history(
                limit=1, kind="on_demand", enforce_limit=True, retry=50
            )
        )
        == 1
    )

    await dev.async_update_health_data()
    assert dev.wifi_name == "ring_mock_wifi"
    assert dev.wifi_signal_category == "good"
    assert dev.wifi_signal_strength != 100


async def test_other_controls(ring, aioresponses_mock):
    dev = ring.devices()["other"][0]

    kwargs = nojson_request_kwargs()

    await dev.async_set_doorbell_volume(6)
    kwargs["params"] = {"doorbot[settings][doorbell_volume]": "6"}
    aioresponses_mock.assert_called_with(
        "https://api.ring.com/clients_api/doorbots/185036587", method="PUT", **kwargs
    )

    kwargs = json_request_kwargs()

    await dev.async_set_mic_volume(10)
    kwargs["json"] = {"volume_settings": {"mic_volume": 10}}
    aioresponses_mock.assert_called_with(
        "https://api.ring.com/devices/v1/devices/185036587/settings",
        method="PATCH",
        **kwargs,
    )

    await dev.async_set_voice_volume(9)
    kwargs["json"] = {"volume_settings": {"voice_volume": 9}}
    aioresponses_mock.assert_called_with(
        "https://api.ring.com/devices/v1/devices/185036587/settings",
        method="PATCH",
        **kwargs,
    )

    await dev.async_set_clip_length_max(30)
    kwargs["json"] = {"video_settings": {"clip_length_max": 30}}
    aioresponses_mock.assert_called_with(
        "https://api.ring.com/devices/v1/devices/185036587/settings",
        method="PATCH",
        **kwargs,
    )

    await dev.async_set_keep_alive_auto(32.2)
    kwargs["json"] = {"keep_alive_settings": {"keep_alive_auto": 32.2}}
    aioresponses_mock.assert_called_with(
        "https://api.ring.com/devices/v1/devices/185036587/settings",
        method="PATCH",
        **kwargs,
    )


async def test_other_invitations(ring, aioresponses_mock):
    dev = ring.devices()["other"][0]
    kwargs = json_request_kwargs()
    kwargs["json"] = {
        "invitation": {
            "doorbot_ids": [185036587],
            "invited_email": "test@example.com",
            "group_ids": [],
        }
    }

    await dev.async_invite_access("test@example.com")
    aioresponses_mock.assert_called_with(
        "https://api.ring.com/clients_api/locations/mock-location-id/invitations",
        method="POST",
        **kwargs,
    )

    await dev.async_remove_access(123456789)

    kwargs = nojson_request_kwargs()
    aioresponses_mock.assert_called_with(
        "https://api.ring.com/clients_api/locations/mock-location-id/invitations/123456789",
        method="DELETE",
        **kwargs,
    )


async def test_other_open_door(ring, aioresponses_mock, mocker):
    dev = ring.devices()["other"][0]

    mocker.patch("uuid.uuid4", return_value="987654321")

    kwargs = json_request_kwargs()
    kwargs["json"] = {
        "command_name": "device_rpc",
        "request": {
            "id": "987654321",
            "jsonrpc": "2.0",
            "method": "unlock_door",
            "params": {"door_id": 0, "user_id": 15},
        },
    }

    await dev.async_open_door(15)
    aioresponses_mock.assert_called_with(
        "https://api.ring.com/commands/v1/devices/185036587/device_rpc",
        method="PUT",
        **kwargs,
    )
