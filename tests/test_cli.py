"""Module for cli tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import DEFAULT, MagicMock, call, patch

import aiofiles
import pytest
from asyncclick.testing import CliRunner
from ring_doorbell import AuthenticationError, Requires2FAError, Ring
from ring_doorbell.cli import (
    _event_handler,
    cli,
    devices_command,
    list_command,
    listen,
    motion_detection,
    show,
    videos,
)
from ring_doorbell.const import GCM_TOKEN_FILE
from ring_doorbell.listen import can_listen

from tests.conftest import load_fixture, load_fixture_as_dict


async def test_cli_default(ring):
    runner = CliRunner()
    with runner.isolated_filesystem():
        res = await runner.invoke(
            cli, ["--username", "foo", "--password", "foo"], obj=ring
        )

        expected = (
            "Name:       Downstairs\nFamily:     chimes\nID:"
            "         999999\nTimezone:   America/New_York\nWifi Name:"
            "  ring_mock_wifi\nWifi RSSI:  -39\n\n"
        )

        assert res.exit_code == 0
        assert expected in res.output


async def test_show(ring):
    runner = CliRunner()
    with runner.isolated_filesystem():
        res = await runner.invoke(show, obj=ring)

        expected = (
            "Name:       Downstairs\nFamily:     chimes\nID:"
            "         999999\nTimezone:   America/New_York\nWifi Name:"
            "  ring_mock_wifi\nWifi RSSI:  -39\n\n"
        )

        assert res.exit_code == 0
        assert expected in res.output


async def test_devices(ring):
    runner = CliRunner()
    with runner.isolated_filesystem():
        res = await runner.invoke(devices_command, obj=ring)

        expected = (
            "(Pretty format coming soon, if you want json "
            "consistently from this command provide the --json flag)\n"
        )
        for device_type in ring.devices_data:
            for device_api_id in ring.devices_data[device_type]:
                expected += (
                    json.dumps(ring.devices_data[device_type][device_api_id], indent=2)
                    + "\n"
                )

        assert res.exit_code == 0
        assert expected == res.output


async def test_list(ring):
    runner = CliRunner()
    with runner.isolated_filesystem():
        res = await runner.invoke(list_command, obj=ring)

        expected = (
            "Front Door (lpd_v1)\nBack Door (lpd_v1)\nDownstairs (chime)\n"
            "Front (hp_cam_v1)\nIngress (intercom_handset_audio)\n"
        )

        assert res.exit_code == 0
        assert expected in res.output


aiofiles.threadpool.wrap.register(MagicMock)(
    lambda *args, **kwargs: aiofiles.threadpool.AsyncBufferedIOBase(*args, **kwargs)
)


async def test_videos(ring, mocker):
    runner = CliRunner()
    mock_file_stream = MagicMock(read=lambda *args, **kwargs: b"")  # noqa: ARG005
    with runner.isolated_filesystem():
        with patch(
            "aiofiles.threadpool.sync_open", return_value=mock_file_stream
        ) as mock_open:
            res = await runner.invoke(videos, ["--count", "--download-all"], obj=ring)
        assert mock_open.call_count == 3
        mock_file_stream.write.assert_has_calls([call(b"123456")] * 3)
        assert "Downloading 3 videos" in res.output


@pytest.mark.parametrize(
    ("affect_method", "exception", "file_exists"),
    [
        (None, None, False),
        ("ring_doorbell.auth.Auth.fetch_token", Requires2FAError, False),
        ("ring_doorbell.ring.Ring.update_data", AuthenticationError, True),
    ],
    ids=("No 2FA", "Require 2FA", "Invalid Grant"),
)
async def test_auth(mocker, affect_method, exception, file_exists):
    call_count = 0

    def _raise_once(self, *_: dict[str, Any], **__: dict[str, Any]) -> dict[str, Any]:
        nonlocal call_count, exception
        if call_count == 0:
            call_count += 1
            msg = "Simulated exception"
            raise exception(msg)
        call_count += 1

        if hasattr(self, "_update_data"):
            return self._update_data()

        return DEFAULT

    def _add_token(
        uri,
        http_method,
        body,
        headers,
        token_placement=None,
        **kwargs,  # noqa: ANN003
    ) -> tuple[str, dict, bytes]:
        return uri, headers, body

    mocker.patch(
        "oauthlib.oauth2.LegacyApplicationClient.add_token", side_effect=_add_token
    )
    mocker.patch.object(Path, "is_file", return_value=file_exists)
    mocker.patch.object(Path, "read_text", return_value=load_fixture("ring_oauth.json"))
    mocker.patch("builtins.input", return_value="Foo")
    mocker.patch("getpass.getpass", return_value="Foo")
    if affect_method is not None:
        mocker.patch(affect_method, side_effect=_raise_once, autospec=True)

    runner = CliRunner()
    with runner.isolated_filesystem():
        res = await runner.invoke(cli)

        assert res.exit_code == 0


async def test_motion_detection(ring, aioresponses_mock, devices_fixture):
    runner = CliRunner()
    with runner.isolated_filesystem():
        res = await runner.invoke(
            motion_detection,
            ["--device-name", "Front"],
            obj=ring,
        )
        expected = "Front (hp_cam_v1) has motion detection off"
        assert res.exit_code == 0
        assert expected in res.output

        res = await runner.invoke(
            motion_detection,
            ["--device-name", "Front", "--off"],
            obj=ring,
        )
        expected = "Front (hp_cam_v1) already has motion detection off"
        assert res.exit_code == 0
        assert expected in res.output

        # Changes the return to indicate that the siren is now on.
        devices_fixture.updated = True
        aioresponses_mock.get(
            "https://api.ring.com/clients_api/ring_devices",
            payload=load_fixture_as_dict("ring_devices_updated.json"),
        )

        res = await runner.invoke(
            motion_detection,
            ["--device-name", "Front", "--on"],
            obj=ring,
        )
        expected = "Front (hp_cam_v1) motion detection set to on"
        assert res.exit_code == 0
        assert expected in res.output


@pytest.mark.skipif(
    can_listen is False, reason="requires the extra [listen] to be installed"
)
@pytest.mark.nolistenmock()
async def test_listen_store_credentials(mocker, auth):
    runner = CliRunner()
    import firebase_messaging

    credentials = json.loads(load_fixture("ring_listen_credentials.json"))

    with runner.isolated_filesystem():
        mocker.patch(
            "firebase_messaging.fcmregister.FcmRegister.gcm_check_in",
            return_value="foobar",
        )
        mocker.patch(
            "firebase_messaging.fcmregister.FcmRegister.register",
            return_value=credentials,
        )
        mocker.patch("firebase_messaging.FcmPushClient.start")
        mocker.patch("firebase_messaging.FcmPushClient.is_started", return_value=True)

        ring = Ring(auth)
        assert not Path(GCM_TOKEN_FILE).is_file()

        await runner.invoke(listen, ["--store-credentials"], obj=ring)
        assert Path(GCM_TOKEN_FILE).is_file()
        assert firebase_messaging.fcmregister.FcmRegister.gcm_check_in.call_count == 0
        assert firebase_messaging.fcmregister.FcmRegister.register.call_count == 1
        assert firebase_messaging.FcmPushClient.start.call_count == 1

        ring = Ring(auth)
        await runner.invoke(listen, ["--store-credentials"], obj=ring)
        assert firebase_messaging.fcmregister.FcmRegister.gcm_check_in.call_count == 1
        assert firebase_messaging.fcmregister.FcmRegister.register.call_count == 1
        assert firebase_messaging.FcmPushClient.start.call_count == 2


@pytest.mark.skipif(
    can_listen is False, reason="requires the extra [listen] to be installed"
)
async def test_listen_event_handler(mocker, auth):
    from ring_doorbell.listen import RingEventListener

    ring = Ring(auth)
    listener = RingEventListener(ring)
    await listener.async_start()
    listener.add_notification_callback(_event_handler(ring).on_event)

    msg = json.loads(load_fixture("ring_listen_fcmdata.json"))
    gcmdata = load_fixture("ring_listen_motion.json")
    msg["data"]["gcmData"] = gcmdata
    echomock = mocker.patch("ring_doorbell.cli.echo")
    mocker.patch(
        "ring_doorbell.cli.get_now_str", return_value="2023-10-24 09:42:18.789709"
    )
    listener._on_notification(msg, "1234567")
    exp = (
        "2023-10-24 09:42:18.789709: RingEvent(id=12345678901234, "
        "doorbot_id=12345678, device_name='Front Floodcam'"
        ", device_kind='floodlight_v2', now=1698137483.395,"
        " expires_in=180, kind='motion', state='human') : "
        "Currently active count = 1"
    )
    echomock.assert_called_with(exp)
