"""Module for listening to firebase cloud messages and updating dings."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import TYPE_CHECKING, Any, Callable

from async_timeout import timeout as asyncio_timeout
from firebase_messaging import FcmPushClient, FcmRegisterConfig

from ring_doorbell.const import (
    API_URI,
    API_VERSION,
    DEFAULT_LISTEN_EVENT_EXPIRES_IN,
    FCM_API_KEY,
    FCM_APP_ID,
    FCM_PROJECT_ID,
    FCM_RING_SENDER_ID,
    KIND_DING,
    KIND_INTERCOM_UNLOCK,
    KIND_MOTION,
    PUSH_ACTION_DING,
    PUSH_ACTION_INTERCOM_UNLOCK,
    PUSH_ACTION_MOTION,
    PUSH_NOTIFICATION_KINDS,
    SUBSCRIPTION_ENDPOINT,
)
from ring_doorbell.event import RingEvent, RingEventKey
from ring_doorbell.exceptions import RingError
from ring_doorbell.util import parse_datetime

from .listenerconfig import RingEventListenerConfig

if TYPE_CHECKING:
    from ring_doorbell.ring import Ring

_logger = logging.getLogger(__name__)

OnNotificationCallable = Callable[[RingEvent], None]
CredentialsUpdatedCallable = Callable[[dict[str, Any]], None]


class RingEventListener:
    """Class to connect to firebase cloud messaging."""

    SESSION_REFRESH_INTERVAL = 60 * 60 * 12

    def __init__(
        self,
        ring: Ring,
        credentials: dict[str, Any] | None = None,
        credentials_updated_callback: CredentialsUpdatedCallable | None = None,
        *,
        config: RingEventListenerConfig | None = None,
    ) -> None:
        """Initialise the event listener with credentials.

        Provide a callback for when credentials are updated by FCM.
        """
        self._ring = ring

        self._callbacks: dict[int, OnNotificationCallable] = {}
        self.subscribed = False
        self.started = False
        self._device_model = self._ring.auth.get_device_model()

        self._credentials = credentials
        self._credentials_updated_callback = credentials_updated_callback

        self._receiver: FcmPushClient | None = None
        self._config: RingEventListenerConfig = (
            config or RingEventListenerConfig.default_config()
        )

        self._subscription_counter = 1
        self._intercom_unlock_counter: dict[int, int] = {}

        self.session_refresh_task: asyncio.Task | None = None
        self.fcm_token: str | None = None

        self._seen_events: set[RingEventKey] = set()

    def _credentials_updated_cb(self, creds: dict[str, Any]) -> None:
        self._credentials = creds
        if self._credentials_updated_callback:
            self._credentials_updated_callback(creds)

    async def add_subscription_to_ring(self, token: str) -> None:
        """Add subscription to ring."""
        if not self._ring.session:
            await self._ring.async_create_session()

        session_patch_data = {
            "device": {
                "metadata": {
                    "api_version": API_VERSION,
                    "device_model": self._device_model,
                    "pn_dict_version": "2.0.0",
                    "pn_service": "fcm",
                },
                "os": "android",
                "push_notification_token": token,
            }
        }
        resp = await self._ring.auth.async_query(
            API_URI + SUBSCRIPTION_ENDPOINT,
            method="PATCH",
            json=session_patch_data,
            raise_for_status=False,
        )
        if resp.status_code != 204:
            _logger.error(
                "Unable to checkin to listen service, "
                "response was %s %s, event listener not started",
                resp.status_code,
                resp.text,
            )
            self.subscribed = False
            return

        self.subscribed = True
        # Update devices for the intercom unlock events
        if not self._ring.devices_data:
            await self._ring.async_update_devices()

    def add_notification_callback(self, callback: OnNotificationCallable) -> int:
        """Add a callback to be notified on event."""
        sub_id = self._subscription_counter

        self._callbacks[sub_id] = callback
        self._subscription_counter += 1

        return sub_id

    def remove_notification_callback(self, subscription_id: int) -> None:
        """Remove a notification callback by id."""
        if subscription_id == 1:
            msg = "Cannot remove the default callback for ring-doorbell with value 1"
            raise RingError(msg)

        if subscription_id not in self._callbacks:
            msg = f"ID {subscription_id} is not a valid callback id"
            raise RingError(msg)

        del self._callbacks[subscription_id]

    async def stop(self) -> None:
        """Stop the listener."""
        self.started = False

        if self._receiver:
            await self._receiver.stop()

        refresh_task = self.session_refresh_task
        self.session_refresh_task = None
        if refresh_task and not refresh_task.done():
            refresh_task.cancel()

        self._callbacks = {}

    async def start(
        self,
        *,
        timeout: int = 10,
    ) -> bool:
        """Start the listener."""
        _logger.debug("Starting event listener")
        if not self._receiver:
            fcm_config = FcmRegisterConfig(
                FCM_PROJECT_ID, FCM_APP_ID, FCM_API_KEY, FCM_RING_SENDER_ID
            )
            self._receiver = FcmPushClient(
                self._on_notification,
                fcm_config,
                self._credentials,
                self._credentials_updated_cb,
                config=self._config,
                http_client_session=self._ring.auth._session,  # noqa: SLF001
            )
        self.fcm_token = await self._receiver.checkin_or_register()
        if not self.fcm_token:
            _logger.error(
                "Ring listener unable to check in to fcm, " "event listener not started"
            )
            return False

        if not self.subscribed:
            await self.add_subscription_to_ring(self.fcm_token)
        if self.subscribed:
            self.add_notification_callback(self._ring._add_event_to_dings_data)  # noqa: SLF001

            async with asyncio_timeout(timeout):
                await self._receiver.start()
            self.started = True
            self.session_refresh_task = asyncio.create_task(
                self._periodic_session_refresh()
            )
            _logger.debug("Started event listener")
        return self.started

    async def _periodic_session_refresh(self) -> None:
        while self.started:
            now = time.monotonic()
            if TYPE_CHECKING:
                assert self._ring.session_refresh_time
                assert self.fcm_token
            since_refresh = now - self._ring.session_refresh_time

            if since_refresh > self.SESSION_REFRESH_INTERVAL:
                _logger.debug("Refreshing ring session")
                await self._ring.async_create_session()
                await self.add_subscription_to_ring(self.fcm_token)
                break

            sleep_for = 1 + time.monotonic() - self._ring.session_refresh_time
            await asyncio.sleep(sleep_for)

    def _get_ding_event(self, gcm_data: dict[str, Any]) -> RingEvent:
        ding = gcm_data["ding"]
        action = gcm_data["action"]
        subtype = gcm_data["subtype"]
        if action.lower() == PUSH_ACTION_MOTION.lower():
            kind = KIND_MOTION
            state = subtype
        elif action.lower == PUSH_ACTION_DING.lower():
            kind = KIND_DING
            state = "ringing"
        else:
            kind = action
            state = subtype

        created_at = ding["created_at"]
        create_seconds = parse_datetime(created_at).timestamp()
        return RingEvent(
            id=ding["id"],
            kind=kind,
            doorbot_id=ding["doorbot_id"],
            device_name=ding["device_name"],
            device_kind=ding["device_kind"],
            now=create_seconds,
            expires_in=DEFAULT_LISTEN_EVENT_EXPIRES_IN,
            state=state,
        )

    def _get_intercom_unlock_event(self, gcm_data: dict[str, Any]) -> RingEvent | None:
        device_api_id = gcm_data["alarm_meta"]["device_zid"]
        if (device := self._ring.get_device_by_api_id(device_api_id)) is None:
            _logger.debug("Event received for unknown device id: %s", device_api_id)
            return None

        if device_api_id not in self._intercom_unlock_counter:
            self._intercom_unlock_counter[device_api_id] = 0
        self._intercom_unlock_counter[device_api_id] += 1
        return RingEvent(
            id=self._intercom_unlock_counter[device_api_id],
            kind=KIND_INTERCOM_UNLOCK,
            doorbot_id=device_api_id,
            device_name=device.name,
            device_kind=device.kind,
            now=time.time(),
            expires_in=DEFAULT_LISTEN_EVENT_EXPIRES_IN,
            state="unlock",
        )

    def _check_is_update(self, ring_event: RingEvent) -> None:
        """Battery doorbells send two events.

        First without an image and the second with an image.
        """
        now = time.time()
        seen_events = {
            key
            for key in self._seen_events
            if (now - key.now) < DEFAULT_LISTEN_EVENT_EXPIRES_IN
        }
        event_key = ring_event.get_key()
        if event_key in seen_events:
            ring_event.is_update = True
        else:
            seen_events.add(event_key)
        self._seen_events = seen_events

    def _on_notification(
        self,
        notification: dict[str, dict[str, str]],
        persistent_id: str,  # noqa: ARG002
        obj: Any | None = None,  # noqa: ARG002
    ) -> None:
        msg_data = notification["data"]
        if "gcmData" in msg_data:
            gcm_data = json.loads(notification["data"]["gcmData"])
            ring_event = self._get_legacy_ring_event(gcm_data)
        else:
            ring_event = self._get_ring_event(msg_data)

        if ring_event:
            self._check_is_update(ring_event)
            _logger.debug("Event received %s", ring_event)
            for callback in self._callbacks.values():
                callback(ring_event)
        else:
            _logger.debug("Unknown event received %s", msg_data)

    def _get_ring_event(self, msg_data: dict) -> RingEvent | None:
        if (android_config_str := msg_data.get("android_config")) is None or (
            data_str := msg_data.get("data")
        ) is None:
            _logger.debug(
                "Unexpected alert type in fcm message data.  Full message is:\n%s",
                json.dumps(msg_data),
            )
            return None

        android_config = json.loads(android_config_str)
        data = json.loads(data_str)
        event_category = android_config["category"]
        event_kind = PUSH_NOTIFICATION_KINDS.get(event_category, "Unknown")
        device = data["device"]
        event = data["event"]
        ding = event["ding"]
        event_id = ding.get("id")
        if event_id is None:
            event_id = event.get("eventito", {}).get("timestamp")
        if event_id is None:
            _logger.debug(
                "Unexpected Ring event without an id. Full message is:\n%s",
                json.dumps(msg_data),
            )
            return None
        created_at = ding["created_at"]
        create_seconds = parse_datetime(created_at).timestamp()
        return RingEvent(
            int(event_id),
            device["id"],
            device_name=device.get("name"),
            device_kind=device.get("kind"),
            kind=event_kind,
            now=create_seconds,
            expires_in=DEFAULT_LISTEN_EVENT_EXPIRES_IN,
            state=ding["subtype"],
        )

    def _get_legacy_ring_event(self, gcm_data: dict) -> RingEvent | None:
        re: RingEvent | None = None
        if "ding" in gcm_data:
            re = self._get_ding_event(gcm_data)
        elif gcm_data.get("action") == PUSH_ACTION_INTERCOM_UNLOCK:
            re = self._get_intercom_unlock_event(gcm_data)
        elif "community_alert" not in gcm_data:
            _logger.debug(
                "Unexpected alert type in gcmData.  Full message is:\n%s",
                json.dumps(gcm_data),
            )
            return None
        return re
