"""Module for listening to firebase cloud messages and updating dings."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import TYPE_CHECKING, Any, Callable, Dict

from firebase_messaging import FcmPushClient

from ring_doorbell.const import (
    API_URI,
    API_VERSION,
    DEFAULT_LISTEN_EVENT_EXPIRES_IN,
    KIND_DING,
    KIND_INTERCOM_UNLOCK,
    KIND_MOTION,
    PUSH_ACTION_DING,
    PUSH_ACTION_INTERCOM_UNLOCK,
    PUSH_ACTION_MOTION,
    RING_SENDER_ID,
    SUBSCRIPTION_ENDPOINT,
)
from ring_doorbell.event import RingEvent
from ring_doorbell.exceptions import RingError
from ring_doorbell.generic import get_time

from .listenerconfig import RingEventListenerConfig

if TYPE_CHECKING:
    from ring_doorbell.ring import Ring

_logger = logging.getLogger(__name__)

OnNotificationCallable = Callable[[RingEvent], None]
CredentialsUpdatedCallable = Callable[[Dict[str, Any]], None]


class RingEventListener:
    """Class to connect to firebase cloud messaging."""

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
        self._app_id = self._ring.auth.get_hardware_id()
        self._device_model = self._ring.auth.get_device_model()

        self._credentials = credentials
        self._credentials_updated_callback = credentials_updated_callback

        self._receiver: FcmPushClient | None = None
        self._config: RingEventListenerConfig = (
            config or RingEventListenerConfig.default_config()
        )

        self._subscription_counter = 1
        self._intercom_unlock_counter: dict[int, int] = {}

    async def async_add_subscription_to_ring(self, token: str) -> None:
        """Add subscription to ring."""
        if not self._ring.session:
            await self._ring.async_create_session()

        session_patch_data = {
            "device": {
                "metadata": {
                    "api_version": API_VERSION,
                    "device_model": self._device_model,
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
        if not self._ring.dings_data:
            await self._ring.async_update_dings()

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

        if len(self._callbacks) == 0 and self._receiver:
            self._receiver.stop()
            self._receiver = None

    def stop(self) -> None:
        """Stop the listener."""
        if self._receiver:
            self.started = False
            self._receiver.stop()
            self._receiver = None

        self._callbacks = {}

    def start(
        self,
        callback: OnNotificationCallable | None = None,
        *,
        listen_loop: asyncio.AbstractEventLoop | None = None,
        callback_loop: asyncio.AbstractEventLoop | None = None,
        timeout: int = 30,
    ) -> bool:
        """Start the listener."""
        return self._ring.auth.run_async_on_event_loop(
            self.async_start(
                callback,
                listen_loop=listen_loop,
                callback_loop=callback_loop,
                timeout=timeout,
            )
        )

    async def async_start(
        self,
        callback: OnNotificationCallable | None = None,
        *,
        listen_loop: asyncio.AbstractEventLoop | None = None,
        callback_loop: asyncio.AbstractEventLoop | None = None,
        timeout: int = 30,
    ) -> bool:
        """Start the listener."""
        if not callback:
            callback = self._ring._add_event_to_dings_data  # noqa: SLF001

        if not self._receiver:
            self._receiver = FcmPushClient(
                credentials=self._credentials,
                credentials_updated_callback=self._credentials_updated_callback,
                config=self._config,
                http_client_session=self._ring.auth.http_client_session,
            )
        fcm_token: str | None = await self._receiver.checkin(
            RING_SENDER_ID, self._app_id
        )
        if not fcm_token:
            _logger.error("Unable to check in to fcm, event listener not started")
            return False

        await self.async_add_subscription_to_ring(fcm_token)
        if self.subscribed:
            self.add_notification_callback(callback)

            self._receiver.start(
                self._on_notification,
                listen_event_loop=listen_loop,
                callback_event_loop=callback_loop,
            )

            start = time.time()
            now = start
            while not self._receiver.is_started() and now - start < timeout:
                await asyncio.sleep(0.1)
                now = time.time()
            self.started = self._receiver.is_started()

        return self.subscribed and self.started

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
        create_seconds = get_time(created_at).timestamp()
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

    def _on_notification(
        self,
        notification: dict[str, dict[str, str]],
        persistent_id: str,  # noqa: ARG002
        obj: Any | None = None,  # noqa: ARG002
    ) -> None:
        gcm_data = json.loads(notification["data"]["gcmData"])

        re: RingEvent | None = None
        if "ding" in gcm_data:
            re = self._get_ding_event(gcm_data)
        elif gcm_data.get("action") == PUSH_ACTION_INTERCOM_UNLOCK:
            re = self._get_intercom_unlock_event(gcm_data)
        elif "community_alert" not in gcm_data:
            _logger.debug(
                "Unexpected alert type in gcmData.  Full message is:\n%s",
                json.dumps(notification),
            )
            return
        if re:
            for callback in self._callbacks.values():
                callback(re)
