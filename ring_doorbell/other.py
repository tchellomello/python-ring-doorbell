# vim:sw=4:ts=4:et:
"""Python Ring Other (Intercom) wrapper."""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import TYPE_CHECKING, Any, ClassVar

import aiofiles

from ring_doorbell.const import (
    DOORBELLS_ENDPOINT,
    HEALTH_DOORBELL_ENDPOINT,
    INTERCOM_ALLOWED_USERS,
    INTERCOM_INVITATIONS_DELETE_ENDPOINT,
    INTERCOM_INVITATIONS_ENDPOINT,
    INTERCOM_KINDS,
    INTERCOM_OPEN_ENDPOINT,
    MIC_VOL_MAX,
    MIC_VOL_MIN,
    MSG_VOL_OUTBOUND,
    OTHER_DOORBELL_VOL_MAX,
    OTHER_DOORBELL_VOL_MIN,
    SETTINGS_ENDPOINT,
    SNAPSHOT_ENDPOINT,
    SNAPSHOT_TIMESTAMP_ENDPOINT,
    VOICE_VOL_MAX,
    VOICE_VOL_MIN,
    RingCapability,
)
from ring_doorbell.exceptions import RingError
from ring_doorbell.generic import RingGeneric
from ring_doorbell.webrtcstream import (
    RingWebRtcMessageCallback,
    RingWebRtcStream,
)

_LOGGER = logging.getLogger(__name__)


class RingOther(RingGeneric):
    """Implementation for Ring Intercom."""

    if TYPE_CHECKING:
        from ring_doorbell.ring import Ring

    def __init__(self, ring: Ring, device_api_id: int, *, shared: bool = False) -> None:
        """Initialise the other devices."""
        super().__init__(ring, device_api_id)
        self.shared = shared
        self._webrtc_streams: dict[str, RingWebRtcStream] = {}

    @property
    def family(self) -> str:
        """Return Ring device family type."""
        return "other"

    async def async_update_health_data(self) -> None:
        """Update health attrs."""
        resp = await self._ring.async_query(
            HEALTH_DOORBELL_ENDPOINT.format(self.device_api_id)
        )
        self._health_attrs = resp.json().get("device_health", {})

    @property
    def model(self) -> str:
        """Return Ring device model name."""
        if self.kind in INTERCOM_KINDS:
            return "Intercom"
        return "Unknown Other"

    def has_capability(self, capability: RingCapability | str) -> bool:
        """Return if device has specific capability."""
        capability = (
            capability
            if isinstance(capability, RingCapability)
            else RingCapability.from_name(capability)
        )
        if capability in [
            RingCapability.OPEN,
            RingCapability.HISTORY,
            RingCapability.DING,
        ]:
            return self.kind in INTERCOM_KINDS

        if capability == RingCapability.VIDEO:
            return self.kind == "intercom_handset_video"

        return False

    @property
    def battery_life(self) -> int | None:
        """Return battery life."""
        if self.kind in INTERCOM_KINDS:
            if self._attrs.get("battery_life") is None:
                return None

            value = int(self._attrs.get("battery_life", 0))
            if value and value > 100:
                value = 100

            return value
        return None

    @property
    def subscribed(self) -> bool:
        """Return if is online."""
        if self.kind in INTERCOM_KINDS:
            result = self._attrs.get("subscribed")
            return result is not None
        return False

    @property
    def has_subscription(self) -> bool:
        """Return boolean if the account has subscription."""
        if self.kind in INTERCOM_KINDS and (features := self._attrs.get("features")):
            return features.get("show_recordings", False)
        return False

    async def async_get_snapshot(
        self, retries: int = 3, delay: int = 1, filename: str | None = None
    ) -> bytes | None:
        """Take a snapshot and download it."""
        payload = {"doorbot_ids": [self._attrs.get("id")]}
        await self._ring.async_query(
            SNAPSHOT_TIMESTAMP_ENDPOINT, method="POST", json=payload
        )
        request_time = time.time()
        for _ in range(retries):
            await asyncio.sleep(delay)
            resp = await self._ring.async_query(
                SNAPSHOT_TIMESTAMP_ENDPOINT, method="POST", json=payload
            )
            response = resp.json()
            timestamps = response.get("timestamps") or []
            if not timestamps:
                continue

            timestamp = timestamps[0].get("timestamp")
            if timestamp is not None and timestamp / 1000 > request_time:
                resp = await self._ring.async_query(
                    SNAPSHOT_ENDPOINT.format(self._attrs.get("id"))
                )
                snapshot = resp.content
                if filename:
                    async with aiofiles.open(filename, "wb") as jpg:
                        await jpg.write(snapshot)
                    return None
                return snapshot

        return None

    @property
    def unlock_duration(self) -> str | None:
        """Return time unlock switch is held closed."""
        return (
            json.loads(self._attrs["settings"]["intercom_settings"]["config"])
            .get("analog", {})
            .get("unlock_duration")
        )

    @property
    def doorbell_volume(self) -> int:
        """Return doorbell volume."""
        if self.kind in INTERCOM_KINDS:
            return self._attrs["settings"].get("doorbell_volume", 0)
        return 0

    async def async_set_doorbell_volume(self, value: int) -> None:
        """Set the doorbell volume."""
        if not (
            (isinstance(value, int))
            and (OTHER_DOORBELL_VOL_MIN <= value <= OTHER_DOORBELL_VOL_MAX)
        ):
            raise RingError(
                MSG_VOL_OUTBOUND.format(OTHER_DOORBELL_VOL_MIN, OTHER_DOORBELL_VOL_MAX)
            )

        params = {
            "doorbot[settings][doorbell_volume]": str(value),
        }
        url = DOORBELLS_ENDPOINT.format(self.device_api_id)
        await self._ring.async_query(url, extra_params=params, method="PUT")

    @property
    def keep_alive_auto(self) -> float | None:
        """The keep alive auto setting."""
        if self.kind in INTERCOM_KINDS:
            return self._attrs["settings"].get("keep_alive_auto")
        return None

    async def async_set_keep_alive_auto(self, value: float) -> None:
        """Update the keep alive auto setting."""
        url = SETTINGS_ENDPOINT.format(self.device_api_id)
        payload = {"keep_alive_settings": {"keep_alive_auto": value}}

        await self._ring.async_query(url, method="PATCH", json=payload)

    @property
    def mic_volume(self) -> int | None:
        """Return mic volume."""
        if self.kind in INTERCOM_KINDS:
            return self._attrs["settings"].get("mic_volume")
        return None

    async def async_set_mic_volume(self, value: int) -> None:
        """Set the mic volume."""
        if not ((isinstance(value, int)) and (MIC_VOL_MIN <= value <= MIC_VOL_MAX)):
            raise RingError(MSG_VOL_OUTBOUND.format(MIC_VOL_MIN, MIC_VOL_MAX))

        url = SETTINGS_ENDPOINT.format(self.device_api_id)
        payload = {"volume_settings": {"mic_volume": value}}

        await self._ring.async_query(url, method="PATCH", json=payload)

    @property
    def voice_volume(self) -> int | None:
        """Return voice volume."""
        if self.kind in INTERCOM_KINDS:
            return self._attrs["settings"].get("voice_volume")
        return None

    async def async_set_voice_volume(self, value: int) -> None:
        """Set the voice volume."""
        if not ((isinstance(value, int)) and (VOICE_VOL_MIN <= value <= VOICE_VOL_MAX)):
            raise RingError(MSG_VOL_OUTBOUND.format(VOICE_VOL_MIN, VOICE_VOL_MAX))

        url = SETTINGS_ENDPOINT.format(self.device_api_id)
        payload = {"volume_settings": {"voice_volume": value}}

        await self._ring.async_query(url, method="PATCH", json=payload)

    async def async_get_clip_length_max(self) -> int | None:
        """Get the Maximum clip length."""
        url = SETTINGS_ENDPOINT.format(self.device_api_id)
        resp = await self._ring.async_query(url, method="GET")
        return resp.json().get("video_settings", {}).get("clip_length_max")

    async def async_set_clip_length_max(self, value: int) -> None:
        """Set the maximum clip length.

        This value sets an effective refractory period on consecutive rigns
        eg if set to default value of 60, rings occuring with 60 seconds of
        first will not be detected.
        """
        url = SETTINGS_ENDPOINT.format(self.device_api_id)
        payload = {"video_settings": {"clip_length_max": value}}
        await self._ring.async_query(url, method="PATCH", json=payload)

    @property
    def connection_status(self) -> str | None:
        """Return connection status."""
        if self.kind in INTERCOM_KINDS:
            return self._attrs.get("alerts", {}).get("connection")
        return None

    async def async_get_allowed_users(self) -> list[dict[str, Any]] | None:
        """Return list of users allowed or invited to access."""
        if self.kind in INTERCOM_KINDS:
            url = INTERCOM_ALLOWED_USERS.format(self.location_id)
            resp = await self._ring.async_query(url, method="GET")
            return resp.json()

        return None

    async def async_open_door(self, user_id: int = -1) -> bool:
        """Open the door."""
        if self.kind in INTERCOM_KINDS:
            url = INTERCOM_OPEN_ENDPOINT.format(self.device_api_id)
            request_id = str(uuid.uuid4())
            # params can also accept:
            # issue_time: in seconds
            # command_timeout: in seconds
            payload = {
                "command_name": "device_rpc",
                "request": {
                    "id": request_id,
                    "jsonrpc": "2.0",
                    "method": "unlock_door",
                    "params": {
                        "door_id": 0,
                        "user_id": user_id,
                    },
                },
            }
            resp = await self._ring.async_query(url, method="PUT", json=payload)
            response = resp.json()
            if response.get("result", {}).get("code", -1) == 0:
                return True

        return False

    async def async_invite_access(self, email: str) -> bool:
        """Invite user."""
        if self.kind in INTERCOM_KINDS:
            url = INTERCOM_INVITATIONS_ENDPOINT.format(self.location_id)
            payload = {
                "invitation": {
                    "doorbot_ids": [self.device_api_id],
                    "invited_email": email,
                    "group_ids": [],
                }
            }
            await self._ring.async_query(url, method="POST", json=payload)
            return True

        return False

    async def async_remove_access(self, user_id: int) -> bool:
        """Remove user access or invitation."""
        if self.kind in INTERCOM_KINDS:
            url = INTERCOM_INVITATIONS_DELETE_ENDPOINT.format(self.location_id, user_id)
            await self._ring.async_query(url, method="DELETE")
            return True

        return False

    async def generate_async_webrtc_stream(
        self,
        sdp_offer: str,
        session_id: str,
        on_message_callback: RingWebRtcMessageCallback,
        *,
        keep_alive_timeout: int | None = 60 * 5,
    ) -> None:
        """Generate the rtc stream."""

        async def _close_callback() -> None:
            await self.close_webrtc_stream(session_id)

        stream = RingWebRtcStream(
            self._ring,
            self.device_api_id,
            on_message_callback=on_message_callback,
            keep_alive_timeout=keep_alive_timeout,
            on_close_callback=_close_callback,
        )
        self._webrtc_streams[session_id] = stream
        await stream.generate(sdp_offer)

    async def on_webrtc_candidate(
        self, session_id: str, candidate: str, multi_line_index: int
    ) -> None:
        """Send an ICE candidate."""
        if stream := self._webrtc_streams.get(session_id):
            await stream.on_ice_candidate(candidate, multi_line_index)
        else:
            msg = "Ice candidate received before stream has been created."
            raise RingError(msg)

    async def close_webrtc_stream(self, session_id: str) -> None:
        """Close the rtc stream."""
        stream = self._webrtc_streams.pop(session_id, None)
        if stream:
            await stream.close()

    def sync_close_webrtc_stream(self, session_id: str) -> None:
        """Close the rtc stream."""
        stream = self._webrtc_streams.pop(session_id, None)
        if stream:
            stream.sync_close()

    DEPRECATED_API_QUERIES: ClassVar = {
        *RingGeneric.DEPRECATED_API_QUERIES,
        "update_health_data",
        "open_door",
        "invite_access",
        "remove_access",
    }
    DEPRECATED_API_PROPERTY_GETTERS: ClassVar = {
        *RingGeneric.DEPRECATED_API_PROPERTY_GETTERS,
        "clip_length_max",
        "allowed_users",
    }
    DEPRECATED_API_PROPERTY_SETTERS: ClassVar = {
        *RingGeneric.DEPRECATED_API_PROPERTY_SETTERS,
        "doorbell_volume",
        "keep_alive_auto",
        "mic_volume",
        "voice_volume",
        "clip_length_max",
    }
