# vim:sw=4:ts=4:et:
"""Python Ring Doorbell wrapper."""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

import aiofiles

from ring_doorbell.const import (
    DEFAULT_VIDEO_DOWNLOAD_TIMEOUT,
    DINGS_ENDPOINT,
    DOORBELL_2_KINDS,
    DOORBELL_3_KINDS,
    DOORBELL_3_PLUS_KINDS,
    DOORBELL_4_KINDS,
    DOORBELL_ELITE_KINDS,
    DOORBELL_EXISTING_TYPE,
    DOORBELL_GEN2_KINDS,
    DOORBELL_KINDS,
    DOORBELL_PRO_2_KINDS,
    DOORBELL_PRO_KINDS,
    DOORBELL_VOL_MAX,
    DOORBELL_VOL_MIN,
    DOORBELL_WIRED_KINDS,
    DOORBELLS_ENDPOINT,
    FILE_EXISTS,
    HEALTH_DOORBELL_ENDPOINT,
    LIVE_STREAMING_ENDPOINT,
    MSG_ALLOWED_VALUES,
    MSG_EXISTING_TYPE,
    MSG_EXPECTED_ATTRIBUTE_NOT_FOUND,
    MSG_VOL_OUTBOUND,
    PEEPHOLE_CAM_KINDS,
    SETTINGS_ENDPOINT,
    SNAPSHOT_ENDPOINT,
    SNAPSHOT_TIMESTAMP_ENDPOINT,
    URL_RECORDING,
    URL_RECORDING_SHARE_PLAY,
    RingCapability,
)
from ring_doorbell.exceptions import RingError
from ring_doorbell.generic import RingGeneric

_LOGGER = logging.getLogger(__name__)


class RingDoorBell(RingGeneric):
    """Implementation for Ring Doorbell."""

    if TYPE_CHECKING:
        from ring_doorbell.ring import Ring

    def __init__(self, ring: Ring, device_api_id: int, *, shared: bool = False) -> None:
        """Initialise the doorbell."""
        super().__init__(ring, device_api_id)
        self.shared = shared

    @property
    def family(self) -> str:
        """Return Ring device family type."""
        return "authorized_doorbots" if self.shared else "doorbots"

    async def async_update_health_data(self) -> None:
        """Update health attrs."""
        resp = await self._ring.async_query(
            HEALTH_DOORBELL_ENDPOINT.format(self.device_api_id)
        )
        self._health_attrs = resp.json().get("device_health", {})

    @property
    def model(self) -> str:  # noqa: C901, PLR0911
        """Return Ring device model name."""
        if self.kind in DOORBELL_KINDS:
            return "Doorbell"
        if self.kind in DOORBELL_2_KINDS:
            return "Doorbell 2"
        if self.kind in DOORBELL_3_KINDS:
            return "Doorbell 3"
        if self.kind in DOORBELL_3_PLUS_KINDS:
            return "Doorbell 3 Plus"
        if self.kind in DOORBELL_4_KINDS:
            return "Doorbell 4"
        if self.kind in DOORBELL_PRO_KINDS:
            return "Doorbell Pro"
        if self.kind in DOORBELL_PRO_2_KINDS:
            return "Doorbell Pro 2"
        if self.kind in DOORBELL_ELITE_KINDS:
            return "Doorbell Elite"
        if self.kind in DOORBELL_WIRED_KINDS:
            return "Doorbell Wired"
        if self.kind in DOORBELL_GEN2_KINDS:
            return "Doorbell (2nd Gen)"
        if self.kind in PEEPHOLE_CAM_KINDS:
            return "Peephole Cam"
        return "Unknown Doorbell"

    def has_capability(self, capability: RingCapability | str) -> bool:  # noqa: PLR0911
        """Return if device has specific capability."""
        capability = (
            capability
            if isinstance(capability, RingCapability)
            else RingCapability.from_name(capability)
        )
        if capability == RingCapability.BATTERY:
            return self.kind in (
                DOORBELL_KINDS
                + DOORBELL_2_KINDS
                + DOORBELL_3_KINDS
                + DOORBELL_3_PLUS_KINDS
                + DOORBELL_4_KINDS
                + DOORBELL_GEN2_KINDS
                + PEEPHOLE_CAM_KINDS
            )
        if capability == RingCapability.KNOCK:
            return self.kind in PEEPHOLE_CAM_KINDS
        if capability == RingCapability.PRE_ROLL:
            return self.kind in DOORBELL_3_PLUS_KINDS
        if capability == RingCapability.VOLUME:
            return True
        if capability == RingCapability.HISTORY:
            return True
        if capability in [
            RingCapability.MOTION_DETECTION,
            RingCapability.VIDEO,
            RingCapability.DING,
        ]:
            return self.kind in (
                DOORBELL_KINDS
                + DOORBELL_2_KINDS
                + DOORBELL_3_KINDS
                + DOORBELL_3_PLUS_KINDS
                + DOORBELL_4_KINDS
                + DOORBELL_PRO_KINDS
                + DOORBELL_PRO_2_KINDS
                + DOORBELL_WIRED_KINDS
                + DOORBELL_GEN2_KINDS
                + PEEPHOLE_CAM_KINDS
            )
        return False

    @property
    def battery_life(self) -> int | None:
        """Return battery life."""
        if (
            bl1 := self._attrs.get("battery_life")
        ) is None and "battery_life_2" not in self._attrs:
            return None

        value = 0
        if bl1:
            value += int(bl1)

        if bl2 := self._attrs.get("battery_life_2"):  # Camera has two battery bays
            value += int(bl2)

        return min(value, 100)

    def _get_chime_setting(self, setting: str) -> Any | None:
        if (settings := self._attrs.get("settings")) and (
            chime_settings := settings.get("chime_settings")
        ):
            return chime_settings.get(setting)
        return None

    @property
    def existing_doorbell_type(self) -> str | None:
        """
        Return existing doorbell type.

        0: Mechanical
        1: Digital
        2: Not Present
        """
        try:
            if (dtype := self._get_chime_setting("type")) is not None:
                return DOORBELL_EXISTING_TYPE[dtype]
        except AttributeError:
            return None
        else:
            return None

    async def async_set_existing_doorbell_type(self, value: int) -> None:
        """
        Return existing doorbell type.

        0: Mechanical
        1: Digital
        2: Not Present
        """
        if value not in DOORBELL_EXISTING_TYPE:
            msg = f"value must be in {MSG_EXISTING_TYPE}"
            raise RingError(msg)
        params = {
            "doorbot[description]": self.name,
            "doorbot[settings][chime_settings][type]": value,
        }
        if self.existing_doorbell_type:
            url = DOORBELLS_ENDPOINT.format(self.device_api_id)
            await self._ring.async_query(url, extra_params=params, method="PUT")
            await self._ring.async_update_devices()

    @property
    def existing_doorbell_type_enabled(self) -> bool | None:
        """Return if existing doorbell type is enabled."""
        if self.existing_doorbell_type:
            if self.existing_doorbell_type == DOORBELL_EXISTING_TYPE[2]:
                return None
            return self._get_chime_setting("enable")
        return False

    async def async_set_existing_doorbell_type_enabled(self, value: int) -> None:
        """Enable/disable the existing doorbell if Digital/Mechanical.

        0: Off
        1: On
        
        """

        if self.existing_doorbell_type:

            if self.existing_doorbell_type == DOORBELL_EXISTING_TYPE[2]:
                msg = f"In-Home chime is not present."
                raise RingError(msg)

            params = {
                "doorbot[description]": self.name,
                "doorbot[settings][chime_settings][enable]": value,
            }
            url = DOORBELLS_ENDPOINT.format(self.device_api_id)
            await self._ring.async_query(url, extra_params=params, method="PUT")
            await self._ring.async_update_devices()

    @property
    def existing_doorbell_type_duration(self) -> int | None:
        """Return duration for Digital chime."""
        if (
            self.existing_doorbell_type
            and self.existing_doorbell_type == DOORBELL_EXISTING_TYPE[1]
        ):
            return self._get_chime_setting("duration")
        return None

    async def async_set_existing_doorbell_type_duration(self, value: int) -> None:
        """Set duration for Digital chime."""
        if self.existing_doorbell_type:
            if not (
                (isinstance(value, int))
                and (DOORBELL_VOL_MIN <= value <= DOORBELL_VOL_MAX)
            ):
                raise RingError(
                    MSG_VOL_OUTBOUND.format(DOORBELL_VOL_MIN, DOORBELL_VOL_MAX)
                )

            if self.existing_doorbell_type == DOORBELL_EXISTING_TYPE[1]:
                params = {
                    "doorbot[description]": self.name,
                    "doorbot[settings][chime_settings][duration]": value,
                }
                url = DOORBELLS_ENDPOINT.format(self.device_api_id)
                await self._ring.async_query(url, extra_params=params, method="PUT")
                await self._ring.async_update_devices()

    async def async_get_last_recording_id(self) -> int | None:
        """Return the last recording ID."""
        try:
            res = await self.async_history(limit=1)
            return res[0].get("id") if res else None
        except (IndexError, TypeError):
            return None

    async def async_get_live_streaming_json(self) -> dict[str, Any] | None:
        """Return JSON for live streaming."""
        url = LIVE_STREAMING_ENDPOINT.format(self.device_api_id)
        req = await self._ring.async_query(url, method="POST")
        if req and req.status_code == 200:
            url = DINGS_ENDPOINT
            try:
                resp = await self._ring.async_query(url)
                return resp.json()[0]
            except (IndexError, TypeError):
                pass
        return None

    async def async_recording_download(
        self,
        recording_id: int,
        filename: str | None = None,
        *,
        override: bool = False,
        timeout: int = DEFAULT_VIDEO_DOWNLOAD_TIMEOUT,
    ) -> bytes | None:
        """Save a recording in MP4 format to a file or return raw."""
        if not self.has_subscription:
            msg = "Your Ring account does not have an active subscription."
            _LOGGER.warning(msg)
            return None

        url = URL_RECORDING.format(recording_id)
        try:
            # Video download needs a longer timeout to get the large video file
            req = await self._ring.async_query(url, timeout=timeout)
            if req.status_code == 200:
                if filename:
                    if Path(filename).is_file() and not override:
                        raise RingError(FILE_EXISTS.format(filename))

                    async with aiofiles.open(filename, "wb") as recording:
                        await recording.write(req.content)
                        return None
                else:
                    return req.content
            else:
                msg = (
                    f"Could not get recording at url {url}, "
                    f"status code is {req.status_code}"
                )
                raise RingError(msg)
        except OSError as error:
            msg = f"Error downloading recording {recording_id}: {error}"
            _LOGGER.exception(msg)
            raise RingError(msg) from error

    async def async_recording_url(self, recording_id: int) -> str | None:
        """Return HTTPS recording URL."""
        if not self.has_subscription:
            msg = "Your Ring account does not have an active subscription."
            _LOGGER.warning(msg)
            return None

        url = URL_RECORDING_SHARE_PLAY.format(recording_id)
        req = await self._ring.async_query(url)
        data = req.json()
        if req and req.status_code == 200 and data is not None:
            return data["url"]
        return None

    @property
    def subscribed(self) -> bool:
        """Return if is online."""
        result = self._attrs.get("subscribed")
        return result is not None

    @property
    def subscribed_motion(self) -> bool:
        """Return if is subscribed_motion."""
        result = self._attrs.get("subscribed_motions")
        return result is not None

    @property
    def has_subscription(self) -> bool:
        """Return boolean if the account has subscription."""
        if features := self._attrs.get("features"):
            return features.get("show_recordings", False)
        return False

    @property
    def volume(self) -> int:
        """Return the volume."""
        return self._attrs["settings"].get("doorbell_volume", 0)

    async def async_set_volume(self, value: int) -> None:
        """Set the volume."""
        if not (
            (isinstance(value, int)) and (DOORBELL_VOL_MIN <= value <= DOORBELL_VOL_MAX)
        ):
            raise RingError(MSG_VOL_OUTBOUND.format(DOORBELL_VOL_MIN, DOORBELL_VOL_MAX))

        params = {
            "doorbot[description]": self.name,
            "doorbot[settings][doorbell_volume]": str(value),
        }
        url = DOORBELLS_ENDPOINT.format(self.device_api_id)
        await self._ring.async_query(url, extra_params=params, method="PUT")
        await self._ring.async_update_devices()

    @property
    def connection_status(self) -> str | None:
        """Return connection status."""
        if alerts := self._attrs.get("alerts"):
            return alerts.get("connection")
        return None

    async def async_get_snapshot(
        self, retries: int = 3, delay: int = 1, filename: str | None = None
    ) -> bytes | None:
        """Take a snapshot and download it."""
        url = SNAPSHOT_TIMESTAMP_ENDPOINT
        payload = {"doorbot_ids": [self._attrs.get("id")]}
        await self._ring.async_query(url, method="POST", json=payload)
        request_time = time.time()
        for _ in range(retries):
            await asyncio.sleep(delay)
            resp = await self._ring.async_query(url, method="POST", json=payload)
            response = resp.json()
            if response["timestamps"][0]["timestamp"] / 1000 > request_time:
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

    def _motion_detection_state(self) -> bool | None:
        if settings := self._attrs.get("settings"):
            return settings.get("motion_detection_enabled")
        return None

    @property
    def motion_detection(self) -> bool:
        """Return motion detection enabled state."""
        return state if (state := self._motion_detection_state()) else False

    async def async_set_motion_detection(self, state: bool) -> None:  # noqa: FBT001
        """Set the motion detection enabled state."""
        values = [True, False]
        if state not in values:
            raise RingError(MSG_ALLOWED_VALUES.format("True, False"))

        if self._motion_detection_state() is None:
            _LOGGER.warning(
                "%s",
                MSG_EXPECTED_ATTRIBUTE_NOT_FOUND.format(
                    "settings[motion_detection_enabled]"
                ),
            )
            return

        url = SETTINGS_ENDPOINT.format(self.device_api_id)
        payload = {"motion_settings": {"motion_detection_enabled": state}}

        await self._ring.async_query(url, method="PATCH", json=payload)
        await self._ring.async_update_devices()

    DEPRECATED_API_QUERIES: ClassVar = {
        *RingGeneric.DEPRECATED_API_QUERIES,
        "update_health_data",
        "recording_download",
        "recording_url",
        "get_snapshot",
    }
    DEPRECATED_API_PROPERTY_GETTERS: ClassVar = {
        *RingGeneric.DEPRECATED_API_PROPERTY_GETTERS,
        "last_recording_id",
        "live_streaming_json",
    }
    DEPRECATED_API_PROPERTY_SETTERS: ClassVar = {
        *RingGeneric.DEPRECATED_API_PROPERTY_SETTERS,
        "existing_doorbell_type",
        "existing_doorbell_type_enabled",
        "existing_doorbell_type_duration",
        "volume",
        "motion_detection",
    }
