"""The tests for the Ring platform."""

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


async def test_modern_event_uses_eventito_timestamp_when_ding_id_missing(
    auth, mocker
):
    """Test a modern event without a ding ID uses its eventito timestamp."""
    ring = Ring(auth)
    listener = RingEventListener(ring)
    await listener.start()
    callback = mocker.Mock()
    listener.add_notification_callback(callback)
    msg = load_alert_v2("camera_motion", 123456782)
    data = json.loads(msg["data"]["data"])
    data["event"]["ding"].pop("id")
    data["event"]["eventito"] = {"timestamp": 1772800029955, "type": "human"}
    msg["data"]["data"] = json.dumps(data)

    listener._on_notification(msg, "1234567")

    event = callback.call_args.args[0]
    assert event.id == 1772800029955
    assert event.doorbot_id == 123456782
    assert event.kind == "motion"

    listener._on_notification(msg, "1234568")

    assert callback.call_count == 2
    assert callback.call_args.args[0].is_update is True


async def test_modern_event_without_identifier_is_ignored(auth, mocker):
    """Test a modern event without any stable identifier is ignored."""
    ring = Ring(auth)
    listener = RingEventListener(ring)
    await listener.start()
    callback = mocker.Mock()
    listener.add_notification_callback(callback)
    msg = load_alert_v2("camera_motion", 123456782)
    data = json.loads(msg["data"]["data"])
    data["event"]["ding"].pop("id")
    msg["data"]["data"] = json.dumps(data)

    listener._on_notification(msg, "1234567")

    callback.assert_not_called()


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
