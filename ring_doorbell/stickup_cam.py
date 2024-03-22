# vim:sw=4:ts=4:et:
"""Python Ring Doorbell wrapper."""

from __future__ import annotations

import logging

from ring_doorbell.const import (
    FLOODLIGHT_CAM_KINDS,
    FLOODLIGHT_CAM_PLUS_KINDS,
    FLOODLIGHT_CAM_PRO_KINDS,
    INDOOR_CAM_GEN2_KINDS,
    INDOOR_CAM_KINDS,
    LIGHTS_ENDPOINT,
    MSG_ALLOWED_VALUES,
    MSG_VOL_OUTBOUND,
    SIREN_DURATION_MAX,
    SIREN_DURATION_MIN,
    SIREN_ENDPOINT,
    SPOTLIGHT_CAM_BATTERY_KINDS,
    SPOTLIGHT_CAM_PLUS_KINDS,
    SPOTLIGHT_CAM_PRO_KINDS,
    SPOTLIGHT_CAM_WIRED_KINDS,
    STICKUP_CAM_BATTERY_KINDS,
    STICKUP_CAM_ELITE_KINDS,
    STICKUP_CAM_GEN3_KINDS,
    STICKUP_CAM_KINDS,
    RingCapability,
)
from ring_doorbell.doorbot import RingDoorBell
from ring_doorbell.exceptions import RingError

_LOGGER = logging.getLogger(__name__)


class RingStickUpCam(RingDoorBell):
    """Implementation for RingStickUpCam."""

    @property
    def family(self) -> str:
        """Return Ring device family type."""
        return "stickup_cams"

    @property
    def model(self) -> str:  # noqa: C901, PLR0911, PLR0912
        """Return Ring device model name."""
        if self.kind in FLOODLIGHT_CAM_KINDS:
            return "Floodlight Cam"
        if self.kind in FLOODLIGHT_CAM_PRO_KINDS:
            return "Floodlight Cam Pro"
        if self.kind in FLOODLIGHT_CAM_PLUS_KINDS:
            return "Floodlight Cam Plus"
        if self.kind in INDOOR_CAM_KINDS:
            return "Indoor Cam"
        if self.kind in INDOOR_CAM_GEN2_KINDS:
            return "Indoor Cam (2nd Gen)"
        if self.kind in SPOTLIGHT_CAM_BATTERY_KINDS:
            return "Spotlight Cam {}".format(
                self._attrs.get("ring_cam_setup_flow", "battery").title()
            )
        if self.kind in SPOTLIGHT_CAM_WIRED_KINDS:
            return "Spotlight Cam {}".format(
                self._attrs.get("ring_cam_setup_flow", "wired").title()
            )
        if self.kind in SPOTLIGHT_CAM_PLUS_KINDS:
            return "Spotlight Cam Plus"
        if self.kind in SPOTLIGHT_CAM_PRO_KINDS:
            return "Spotlight Cam Pro"
        if self.kind in STICKUP_CAM_KINDS:
            return "Stick Up Cam"
        if self.kind in STICKUP_CAM_BATTERY_KINDS:
            return "Stick Up Cam Battery"
        if self.kind in STICKUP_CAM_ELITE_KINDS:
            return "Stick Up Cam Wired"
        if self.kind in STICKUP_CAM_GEN3_KINDS:
            return "Stick Up Cam (3rd Gen)"
        _LOGGER.error("Unknown kind: %s", self.kind)
        return "Unknown Stickup Cam"

    def has_capability(self, capability: RingCapability | str) -> bool:
        """Return if device has specific capability."""
        capability = (
            capability
            if isinstance(capability, RingCapability)
            else RingCapability.from_name(capability)
        )
        if capability == RingCapability.HISTORY:
            return True
        if capability == RingCapability.BATTERY:
            return self.kind in (
                SPOTLIGHT_CAM_BATTERY_KINDS
                + STICKUP_CAM_KINDS
                + STICKUP_CAM_BATTERY_KINDS
                + STICKUP_CAM_GEN3_KINDS
            )
        if capability == RingCapability.LIGHT:
            return self.kind in (
                FLOODLIGHT_CAM_KINDS
                + FLOODLIGHT_CAM_PRO_KINDS
                + FLOODLIGHT_CAM_PLUS_KINDS
                + SPOTLIGHT_CAM_BATTERY_KINDS
                + SPOTLIGHT_CAM_WIRED_KINDS
                + SPOTLIGHT_CAM_PLUS_KINDS
                + SPOTLIGHT_CAM_PRO_KINDS
            )
        if capability == RingCapability.SIREN:
            return self.kind in (
                FLOODLIGHT_CAM_KINDS
                + FLOODLIGHT_CAM_PRO_KINDS
                + FLOODLIGHT_CAM_PLUS_KINDS
                + INDOOR_CAM_KINDS
                + INDOOR_CAM_GEN2_KINDS
                + SPOTLIGHT_CAM_BATTERY_KINDS
                + SPOTLIGHT_CAM_WIRED_KINDS
                + SPOTLIGHT_CAM_PLUS_KINDS
                + SPOTLIGHT_CAM_PRO_KINDS
                + STICKUP_CAM_BATTERY_KINDS
                + STICKUP_CAM_ELITE_KINDS
                + STICKUP_CAM_GEN3_KINDS
            )
        if capability in [RingCapability.MOTION_DETECTION, RingCapability.VIDEO]:
            return self.kind in (
                FLOODLIGHT_CAM_KINDS
                + FLOODLIGHT_CAM_PRO_KINDS
                + FLOODLIGHT_CAM_PLUS_KINDS
                + INDOOR_CAM_KINDS
                + INDOOR_CAM_GEN2_KINDS
                + SPOTLIGHT_CAM_BATTERY_KINDS
                + SPOTLIGHT_CAM_WIRED_KINDS
                + SPOTLIGHT_CAM_PLUS_KINDS
                + SPOTLIGHT_CAM_PRO_KINDS
                + STICKUP_CAM_KINDS
                + STICKUP_CAM_BATTERY_KINDS
                + STICKUP_CAM_ELITE_KINDS
                + STICKUP_CAM_GEN3_KINDS
            )
        return False

    @property
    def lights(self) -> str:
        """Return lights status."""
        return self._attrs.get("led_status", "")

    @lights.setter
    def lights(self, state: str) -> None:
        """Control the lights."""
        self._ring.auth.run_async_on_event_loop(self.async_set_lights(state))

    async def async_set_lights(self, state: str) -> None:
        """Control the lights."""
        values = ["on", "off"]
        if state not in values:
            raise RingError(MSG_ALLOWED_VALUES.format(", ".join(values)))

        url = LIGHTS_ENDPOINT.format(self.device_api_id, state)
        await self._ring.async_query(url, method="PUT")
        await self._ring.async_update_devices()

    @property
    def siren(self) -> int:
        """Return siren status."""
        if siren_status := self._attrs.get("siren_status"):
            return siren_status.get("seconds_remaining", 0)
        return 0

    @siren.setter
    def siren(self, duration: int) -> None:
        """Control the siren."""
        self._ring.auth.run_async_on_event_loop(self.async_set_siren(duration))

    async def async_set_siren(self, duration: int) -> None:
        """Control the siren."""
        if not (
            (isinstance(duration, int))
            and (SIREN_DURATION_MIN <= duration <= SIREN_DURATION_MAX)
        ):
            raise RingError(
                MSG_VOL_OUTBOUND.format(SIREN_DURATION_MIN, SIREN_DURATION_MAX)
            )

        if duration > 0:
            state = "on"
            params = {"duration": duration}
        else:
            state = "off"
            params = {}
        url = SIREN_ENDPOINT.format(self.device_api_id, state)
        await self._ring.async_query(url, extra_params=params, method="PUT")
        await self._ring.async_update_devices()
