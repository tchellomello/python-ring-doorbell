"""The tests for the Ring platform."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from ring_doorbell.const import SNAPSHOT_ENDPOINT, SNAPSHOT_TIMESTAMP_ENDPOINT
from ring_doorbell.exceptions import RingError

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
    assert await dev.async_get_clip_length_max() == 60
    assert dev.connection_status == "online"
    assert len(await dev.async_get_allowed_users()) == 2
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

    kwargs = json_request_kwargs()
    kwargs["json"] = None

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


async def test_intercom_video_webrtc_lifecycle(ring, mocker):
    """Test creating, updating, and closing a video intercom WebRTC stream."""
    dev = ring.devices()["other"][0]
    dev._attrs["kind"] = "intercom_handset_video"
    callback = AsyncMock()
    stream = MagicMock()
    stream.generate = AsyncMock()
    stream.on_ice_candidate = AsyncMock()
    stream.close = AsyncMock()
    stream_type = mocker.patch(
        "ring_doorbell.other.RingWebRtcStream", return_value=stream
    )

    assert dev.has_capability("video") is True

    await dev.generate_async_webrtc_stream("offer", "session", callback)
    stream_type.assert_called_once_with(
        dev._ring,
        dev.device_api_id,
        on_message_callback=callback,
        keep_alive_timeout=300,
        on_close_callback=mocker.ANY,
    )
    stream.generate.assert_awaited_once_with("offer")

    await dev.on_webrtc_candidate("session", "candidate", 2)
    stream.on_ice_candidate.assert_awaited_once_with("candidate", 2)

    await dev.close_webrtc_stream("session")
    stream.close.assert_awaited_once_with()
    assert "session" not in dev._webrtc_streams


async def test_intercom_stream_close_callback_removes_session(ring, mocker):
    """A remotely closed stream is removed and cannot receive more candidates."""
    dev = ring.devices()["other"][0]
    stream = MagicMock(generate=AsyncMock(), close=AsyncMock())
    stream_type = mocker.patch(
        "ring_doorbell.other.RingWebRtcStream", return_value=stream
    )
    await dev.generate_async_webrtc_stream("offer", "session", AsyncMock())

    await stream_type.call_args.kwargs["on_close_callback"]()

    assert "session" not in dev._webrtc_streams
    stream.close.assert_awaited_once_with()
    await dev.close_webrtc_stream("session")
    stream.close.assert_awaited_once_with()
    with pytest.raises(RingError, match="before stream has been created"):
        await dev.on_webrtc_candidate("session", "candidate", 1)


async def test_intercom_video_webrtc_sync_close(ring, mocker):
    """Test synchronously closing a video intercom WebRTC stream."""
    dev = ring.devices()["other"][0]
    stream = MagicMock()
    stream.generate = AsyncMock()
    mocker.patch("ring_doorbell.other.RingWebRtcStream", return_value=stream)

    await dev.generate_async_webrtc_stream("offer", "session", AsyncMock())
    dev.sync_close_webrtc_stream("session")

    stream.sync_close.assert_called_once_with()
    assert "session" not in dev._webrtc_streams


async def test_intercom_snapshot_handles_empty_timestamps(ring, mocker):
    """Test an empty Ring timestamp response does not raise an exception."""
    dev = ring.devices()["other"][0]
    empty_response = MagicMock()
    empty_response.json.return_value = {"timestamps": []}
    query = mocker.patch.object(
        dev._ring,
        "async_query",
        new=AsyncMock(return_value=empty_response),
    )
    mocker.patch("ring_doorbell.other.asyncio.sleep", new=AsyncMock())

    assert await dev.async_get_snapshot(retries=2, delay=0) is None
    assert query.await_count == 3


@pytest.mark.parametrize("save_to_file", [False, True], ids=["bytes", "file"])
async def test_intercom_snapshot_downloads_only_fresh_image(
    ring, mocker, tmp_path, save_to_file
):
    """Ignore stale timestamps and return or save the freshly downloaded image."""
    dev = ring.devices()["other"][0]
    dev._attrs["kind"] = "intercom_handset_video"
    mocker.patch("ring_doorbell.other.time.time", return_value=100)
    sleep = mocker.patch("ring_doorbell.other.asyncio.sleep", new=AsyncMock())
    snapshot = b"fresh intercom snapshot"
    query = mocker.patch.object(
        dev._ring,
        "async_query",
        new=AsyncMock(
            side_effect=[
                MagicMock(),
                MagicMock(json=MagicMock(return_value={"timestamps": []})),
                MagicMock(json=MagicMock(return_value={"timestamps": [{}]})),
                MagicMock(
                    json=MagicMock(return_value={"timestamps": [{"timestamp": 100000}]})
                ),
                MagicMock(
                    json=MagicMock(return_value={"timestamps": [{"timestamp": 101000}]})
                ),
                MagicMock(content=snapshot),
            ]
        ),
    )
    filename = tmp_path / "snapshot.jpg"

    result = await dev.async_get_snapshot(
        retries=4, delay=1, filename=str(filename) if save_to_file else None
    )

    assert result == (None if save_to_file else snapshot)
    assert filename.exists() is save_to_file
    if save_to_file:
        assert filename.read_bytes() == snapshot
    timestamp_call = mocker.call(
        SNAPSHOT_TIMESTAMP_ENDPOINT,
        method="POST",
        json={"doorbot_ids": [dev.id]},
    )
    assert query.await_args_list == [timestamp_call] * 5 + [
        mocker.call(SNAPSHOT_ENDPOINT.format(dev.id))
    ]
    assert sleep.await_args_list == [mocker.call(1)] * 4
