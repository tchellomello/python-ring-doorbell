# vim:sw=4:ts=4:et:
"""Python Ring Chime wrapper."""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from ring_doorbell.const import (
    CHIME_2ND_GEN_KINDS,
    CHIME_KINDS,
    CHIME_PRO_KINDS,
    CHIME_TEST_SOUND_KINDS,
    CHIME_VOL_MAX,
    CHIME_VOL_MIN,
    CHIMES_ENDPOINT,
    HEALTH_CHIMES_ENDPOINT,
    LINKED_CHIMES_ENDPOINT,
    MSG_VOL_OUTBOUND,
    TESTSOUND_CHIME_ENDPOINT,
    RingCapability,
    RingEventKind,
)
from ring_doorbell.exceptions import RingError
from ring_doorbell.generic import RingGeneric

_LOGGER = logging.getLogger(__name__)


class RingChime(RingGeneric):
    """Implementation for Ring Chime."""

    @property
    def family(self) -> str:
        """Return Ring device family type."""
        return "chimes"

    async def async_update_health_data(self) -> None:
        """Update health attrs."""
        resp = await self._ring.async_query(
            HEALTH_CHIMES_ENDPOINT.format(self.device_api_id)
        )
        self._health_attrs = resp.json().get("device_health", {})

    @property
    def model(self) -> str:
        """Return Ring device model name."""
        if self.kind in CHIME_KINDS:
            return "Chime"
        if self.kind in CHIME_PRO_KINDS:
            return "Chime Pro"
        if self.kind in CHIME_2ND_GEN_KINDS:
            return "Chime (2nd Gen)"
        return "Unknown Chime"

    def has_capability(self, capability: RingCapability | str) -> bool:
        """Return if device has specific capability."""
        capability = (
            capability
            if isinstance(capability, RingCapability)
            else RingCapability.from_name(capability)
        )
        return capability == RingCapability.VOLUME

    @property
    def volume(self) -> int:
        """Return the chime volume."""
        return self._attrs["settings"].get("volume", 0)

    async def async_set_volume(self, value: int) -> None:
        """Set the chime volume."""
        if not ((isinstance(value, int)) and (CHIME_VOL_MIN <= value <= CHIME_VOL_MAX)):
            raise RingError(MSG_VOL_OUTBOUND.format(CHIME_VOL_MIN, CHIME_VOL_MAX))

        params = {
            "chime[description]": self.name,
            "chime[settings][volume]": str(value),
        }
        url = CHIMES_ENDPOINT.format(self.device_api_id)
        await self._ring.async_query(url, extra_params=params, method="PUT")

    async def async_get_linked_tree(self) -> dict[str, Any]:
        """Return doorbell data linked to chime."""
        url = LINKED_CHIMES_ENDPOINT.format(self.device_api_id)
        resp = await self._ring.async_query(url)
        return resp.json()

    async def async_test_sound(
        self, kind: RingEventKind | str = RingEventKind.DING
    ) -> bool:
        """Play chime to test sound."""
        kind_str = kind.value if isinstance(kind, RingEventKind) else kind
        if kind_str not in CHIME_TEST_SOUND_KINDS:
            return False
        url = TESTSOUND_CHIME_ENDPOINT.format(self.device_api_id)
        await self._ring.async_query(
            url, method="POST", extra_params={"kind": kind_str}
        )
        return True

    DEPRECATED_API_QUERIES: ClassVar = {
        *RingGeneric.DEPRECATED_API_QUERIES,
        "update_health_data",
        "test_sound",
    }
    DEPRECATED_API_PROPERTY_GETTERS: ClassVar = {
        *RingGeneric.DEPRECATED_API_PROPERTY_GETTERS,
        "linked_tree",
    }
    DEPRECATED_API_PROPERTY_SETTERS: ClassVar = {
        *RingGeneric.DEPRECATED_API_PROPERTY_SETTERS,
        "volume",
    }
