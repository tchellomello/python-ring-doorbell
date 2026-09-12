"""The tests for the Ring platform."""

import asyncio
import datetime
import json

import pytest
from freezegun.api import FrozenDateTimeFactory
from ring_doorbell import Ring
from ring_doorbell.exceptions import RingError
from ring_doorbell.listen import RingEventListener

from tests.conftest import load_alert_v1, load_alert_v2, load_fixture


async def test_listen(auth, mocker):
    import firebase_messaging

    ring = Ring(auth)
    listener = RingEventListener(ring)

    await listener.start()
    assert firebase_messaging.FcmPushClient.checkin_or_register.call_count == 1
    assert firebase_messaging.FcmPushClient.start.call_count == 1
    assert listener.subscribed is True
    assert listener.started is True

    with pytest.raises(RingError, match="ID 10 is not a valid callback id"):
        listener.remove_notification_callback(10)

    with pytest.raises(
        RingError,
        match="Cannot remove the default callback for ring-doorbell with value 1",
    ):
        listener.remove_notification_callback(1)

    cbid = listener.add_notification_callback(lambda: 2)
    del listener._callbacks[1]
    listener.remove_notification_callback(cbid)


async def test_listen_waits_until_receiver_is_logged_in(auth):
    import firebase_messaging

    receiver_started = firebase_messaging.FcmPushClient.is_started
    receiver_started.return_value = False

    async def mark_receiver_started() -> None:
        await asyncio.sleep(0)
        receiver_started.return_value = True

    ring = Ring(auth)
    listener = RingEventListener(ring)
    ready_task = asyncio.create_task(mark_receiver_started())

    assert await listener.start(timeout=1) is True
    await ready_task
    assert listener.started is True
    await listener.stop()


async def test_started_tracks_receiver_health(auth):
    import firebase_messaging

    ring = Ring(auth)
    listener = RingEventListener(ring)
    await listener.start()
    assert listener.started is True

    firebase_messaging.FcmPushClient.is_started.return_value = False

    assert listener.started is False
    await listener.stop()
    firebase_messaging.FcmPushClient.stop.assert_awaited_once()


async def test_concurrent_starts_share_one_receiver(auth):
    import firebase_messaging

    ring = Ring(auth)
    listener = RingEventListener(ring)

    assert await asyncio.gather(listener.start(), listener.start()) == [True, True]
    firebase_messaging.FcmPushClient.checkin_or_register.assert_awaited_once()
    firebase_messaging.FcmPushClient.start.assert_awaited_once()
    await listener.stop()


async def test_listen_timeout_cleans_up_partial_receiver(auth):
    import firebase_messaging

    firebase_messaging.FcmPushClient.is_started.return_value = False
    ring = Ring(auth)
    listener = RingEventListener(ring)

    with pytest.raises(TimeoutError):
        await listener.start(timeout=0)

    assert listener.started is False
    assert listener.subscribed is False
    assert listener._receiver is None
    firebase_messaging.FcmPushClient.stop.assert_awaited_once()


async def test_checkin_error_is_not_masked_by_pre_start_cleanup(auth):
    import firebase_messaging

    firebase_messaging.FcmPushClient.checkin_or_register.side_effect = ValueError(
        "registration failed"
    )
    ring = Ring(auth)
    listener = RingEventListener(ring)

    with pytest.raises(ValueError, match="registration failed"):
        await listener.start()

    assert listener.started is False
    assert listener._receiver is None
    firebase_messaging.FcmPushClient.stop.assert_not_awaited()


async def test_callback_added_before_start_is_removable(auth):
    ring = Ring(auth)
    listener = RingEventListener(ring)
    callback_id = listener.add_notification_callback(lambda _: None)

    await listener.start()

    listener.remove_notification_callback(callback_id)
    with pytest.raises(
        RingError,
        match="Cannot remove the default callback for ring-doorbell with value 2",
    ):
        listener.remove_notification_callback(2)
    await listener.stop()


async def test_active_dings(auth, mocker):
    import firebase_messaging

    ring = Ring(auth)
    listener = RingEventListener(ring)
    await listener.start()
    assert firebase_messaging.FcmPushClient.checkin_or_register.call_count == 1
    assert firebase_messaging.FcmPushClient.start.call_count == 1
    assert listener.subscribed is True
    assert listener.started is True
    num_active = len(ring.active_alerts())
    assert num_active == 0
    alertstoadd = 2
    for i in range(alertstoadd):
        msg = load_alert_v1("doorbot_ding", 123456781, ding_id_inc=i)
        listener._on_notification(msg, "1234567" + str(i))
        msg = load_alert_v2("camera_motion", 123456782, ding_id_inc=i)
        listener._on_notification(msg, "1234567" + str(i))
        msg = load_alert_v1("intercom_unlock", 185036587, ding_id_inc=i)
        listener._on_notification(msg, "1234567" + str(i))

    dings = ring.active_alerts()
    assert len(dings) == num_active + alertstoadd * 3
    # Test with the same id which should overwrite
    # previous and keep the overall count the same
    for i in range(alertstoadd):
        msg = load_alert_v1("doorbot_ding", 123456781, ding_id_inc=i)
        listener._on_notification(msg, "1234567" + str(i))
        msg = load_alert_v2("camera_motion", 123456782, ding_id_inc=i)
        listener._on_notification(msg, "1234567" + str(i))

    dings = ring.active_alerts()
    assert len(dings) == num_active + alertstoadd * 3
    await listener.stop()


async def test_ding_expirey(auth, mocker, freezer: FrozenDateTimeFactory):
    ring = Ring(auth)
    listener = RingEventListener(ring)
    await listener.start()

    assert listener.subscribed is True
    assert listener.started is True

    assert len(ring.push_dings_data) == 0
    assert len(ring.active_alerts()) == 0

    alertstoadd = 2
    for i in range(alertstoadd):
        msg = load_alert_v1("doorbot_ding", 123456781, ding_id_inc=i)
        listener._on_notification(msg, "1234567" + str(i))
        msg = load_alert_v2("camera_motion", 123456782, ding_id_inc=i)
        listener._on_notification(msg, "1234567" + str(i))
        msg = load_alert_v1("intercom_unlock", 185036587, ding_id_inc=i)
        listener._on_notification(msg, "1234567" + str(i))

    assert len(ring.push_dings_data) == 6
    assert len(ring.active_alerts()) == 6

    freezer.tick(datetime.timedelta(minutes=5))

    msg = load_alert_v1("doorbot_ding", 123456781, ding_id_inc=alertstoadd + 1)
    listener._on_notification(msg, "123456781" + str(alertstoadd + 1))

    assert len(ring.push_dings_data) == 1
    assert len(ring.active_alerts()) == 1


@pytest.mark.nolistenmock
async def test_listen_subscribe_fail(auth, mocker, caplog, putpatch_status_fixture):
    checkinmock = mocker.patch(
        "firebase_messaging.FcmPushClient.checkin_or_register", return_value="foobar"
    )
    connectmock = mocker.patch("firebase_messaging.FcmPushClient.start")
    mocker.patch("firebase_messaging.FcmPushClient.is_started", return_value=True)

    putpatch_status_fixture.overrides["https://api.ring.com/clients_api/device"] = 401

    ring = Ring(auth)
    listener = RingEventListener(ring)
    await listener.start()
    # Check in gets and error so register is called
    assert checkinmock.call_count == 1
    assert listener.subscribed is False
    assert listener.started is False
    assert connectmock.call_count == 0

    exp = (
        "Unable to checkin to listen service, "
        "response was 401 , event listener not started"
    )
    assert (
        len(
            [
                record
                for record in caplog.records
                if record.levelname == "ERROR" and record.message == exp
            ]
        )
        == 1
    )


@pytest.mark.nolistenmock
async def test_listen_gcm_fail(auth, mocker):
    # Check in gets and error so register is called, the subscribe gets an error
    credentials = json.loads(load_fixture("ring_listen_credentials.json"))
    checkinmock = mocker.patch(
        "firebase_messaging.fcmregister.FcmRegister.gcm_check_in", return_value=None
    )
    registermock = mocker.patch(
        "firebase_messaging.fcmregister.FcmRegister.register", return_value=credentials
    )
    connectmock = mocker.patch("firebase_messaging.FcmPushClient.start")
    mocker.patch("firebase_messaging.FcmPushClient.is_started", return_value=True)

    ring = Ring(auth)
    listener = RingEventListener(ring, credentials)
    await listener.start()
    # Check in gets and error so register is called
    assert checkinmock.call_count == 1
    assert registermock.call_count == 1
    assert listener.subscribed is True
    assert listener.started is True
    assert connectmock.call_count == 1


@pytest.mark.nolistenmock
async def test_listen_fcm_fail(auth, mocker, caplog):
    checkinmock = mocker.patch(
        "firebase_messaging.FcmPushClient.checkin_or_register", return_value=None
    )
    connectmock = mocker.patch("firebase_messaging.FcmPushClient.start")
    mocker.patch("firebase_messaging.FcmPushClient.is_started", return_value=True)

    ring = Ring(auth)
    listener = RingEventListener(ring)
    await listener.start()
    # Check in gets and error so register is called
    assert checkinmock.call_count == 1

    assert listener.subscribed is False
    assert listener.started is False
    assert connectmock.call_count == 0
    exp = "Ring listener unable to check in to fcm, event listener not started"
    assert (
        len(
            [
                record
                for record in caplog.records
                if record.levelname == "ERROR" and record.message == exp
            ]
        )
        == 1
    )
