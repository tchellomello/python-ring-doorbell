# vim:sw=4:ts=4:et:
"""Python Ring Doorbell module."""
import logging
from time import time
from typing import List

from ring_doorbell import RingEvent
from ring_doorbell.auth import Auth
from ring_doorbell.chime import RingChime
from ring_doorbell.doorbot import RingDoorBell
from ring_doorbell.group import RingLightGroup
from ring_doorbell.other import RingOther
from ring_doorbell.stickup_cam import RingStickUpCam

from .const import (
    API_URI,
    API_VERSION,
    DEVICES_ENDPOINT,
    DINGS_ENDPOINT,
    GROUPS_ENDPOINT,
    NEW_SESSION_ENDPOINT,
)

_logger = logging.getLogger(__name__)


TYPES = {
    "stickup_cams": RingStickUpCam,
    "chimes": RingChime,
    "doorbots": RingDoorBell,
    "authorized_doorbots": lambda ring, description: RingDoorBell(
        ring, description, shared=True
    ),
    "other": RingOther,
}


# pylint: disable=useless-object-inheritance
class Ring:
    """A Python Abstraction object to Ring Door Bell."""

    def __init__(self, auth: Auth, *, debug_log_queries=False):
        """Initialize the Ring object."""
        self.auth: Auth = auth
        self.session = None
        self.subscription = None
        self.devices_data = None
        self.chime_health_data = None
        self.doorbell_health_data = None
        self.dings_data = None
        self.push_dings_data = []
        self.groups_data = None
        self.init_loop = None
        self.debug_log_queries = debug_log_queries

    def update_data(self):
        """Update all data."""
        self._update_data()

    def _update_data(self):
        if self.session is None:
            self.create_session()

        self.update_devices()

        self.update_dings()

        self.update_groups()

    def add_event_to_dings_data(self, ring_event: RingEvent):
        # Purge expired push_dings
        now = time()
        self.push_dings_data = [
            re for re in self.push_dings_data if now < re.now + re.expires_in
        ]
        self.push_dings_data.append(ring_event)

    def create_session(self):
        """Create a new Ring session."""
        session_post_data = {
            "device": {
                "hardware_id": self.auth.get_hardware_id(),
                "metadata": {
                    "api_version": API_VERSION,
                    "device_model": self.auth.get_device_model(),
                },
                "os": "android",
            }
        }

        self.session = self._query(
            NEW_SESSION_ENDPOINT,
            method="POST",
            json=session_post_data,
        ).json()

    def update_devices(self):
        """Update device data."""
        if self.session is None:
            self.create_session()

        data = self._query(DEVICES_ENDPOINT).json()

        # Index data by device ID.
        self.devices_data = {
            device_type: {obj["id"]: obj for obj in devices}
            for device_type, devices in data.items()
        }

    def update_dings(self):
        """Update dings data."""
        if self.session is None:
            self.create_session()

        self.dings_data = self._query(DINGS_ENDPOINT).json()

    def update_groups(self):
        """Update groups data."""
        if self.session is None:
            self.create_session()
        # Get all locations
        locations = set()
        for devices in self.devices_data.values():
            for dev in devices.values():
                if "location_id" in dev:
                    locations.add(dev["location_id"])

        # Query for groups
        self.groups_data = {}
        locations.discard(None)
        for location in locations:
            data = self._query(GROUPS_ENDPOINT.format(location)).json()
            if data["device_groups"] is not None:
                for group in data["device_groups"]:
                    self.groups_data[group["device_group_id"]] = group

    def query(
        self,
        url,
        method="GET",
        extra_params=None,
        data=None,
        json=None,
        timeout=None,
        base_uri=API_URI,
    ):
        """Query data from Ring API."""
        if self.session is None:
            self.create_session()
        return self._query(url, method, extra_params, data, json, timeout, base_uri)

    def _query(
        self,
        url,
        method="GET",
        extra_params=None,
        data=None,
        json=None,
        timeout=None,
        base_uri=API_URI,
    ):
        if self.debug_log_queries:
            _logger.debug(
                "url: %s\nmethod: %s\njson: %s\ndata: %s\n extra_params: %s",
                url,
                method,
                json,
                data,
                extra_params,
            )
        response = self.auth.query(
            base_uri + url,
            method=method,
            extra_params=extra_params,
            data=data,
            json=json,
            timeout=timeout,
        )
        if self.debug_log_queries:
            _logger.debug("response_text %s", response.text)
        return response

    def devices(self):
        """Get all devices."""
        devices = {}

        for dev_type, convertor in TYPES.items():
            devices[dev_type] = [
                convertor(self, obj["id"])
                for obj in self.devices_data.get(dev_type, {}).values()
            ]

        return devices

    def get_device_list(self):
        """Get a combined list of all devices."""
        devices = self.devices()
        return (
            devices["doorbots"]
            + devices["authorized_doorbots"]
            + devices["stickup_cams"]
            + devices["chimes"]
            + devices["other"]
        )

    def get_device_by_name(self, device_name):
        """Return a device using it's name."""
        all_devices = self.get_device_list()
        names_to_idx = {device.name: idx for (idx, device) in enumerate(all_devices)}
        device = (
            None
            if device_name not in names_to_idx
            else all_devices[names_to_idx[device_name]]
        )
        return device

    def get_device_by_api_id(self, device_api_id):
        """Return a device using it's id."""
        all_devices = self.get_device_list()
        api_id_to_idx = {
            device.device_api_id: idx for (idx, device) in enumerate(all_devices)
        }
        device = (
            None
            if device_api_id not in api_id_to_idx
            else all_devices[api_id_to_idx[device_api_id]]
        )
        return device

    def video_devices(self):
        """Get all devices."""
        devices = self.devices()

        return (
            devices["doorbots"]
            + devices["authorized_doorbots"]
            + devices["stickup_cams"]
        )

    def groups(self):
        """Get all groups."""
        groups = {}

        for group_id in self.groups_data:
            groups[group_id] = RingLightGroup(self, group_id)

        return groups

    def active_alerts(self) -> List[RingEvent]:
        """Get active alerts."""
        now = time()
        # Purge expired push_dings
        self.push_dings_data = [
            re for re in self.push_dings_data if now < re.now + re.expires_in
        ]
        # Get unique id dictionary
        alerts = {}
        for re in self.push_dings_data:
            key = (re.doorbot_id, re.id, re.kind)
            if key not in alerts or re.now > alerts[key].now:
                alerts[key] = re

        for ding_data in self.dings_data:
            expires_at = ding_data.get("now") + ding_data.get("expires_in")

            if now < expires_at:
                re = RingEvent(
                    id=ding_data["id"],
                    doorbot_id=ding_data["doorbot_id"],
                    device_name=ding_data["doorbot_description"],
                    device_kind=ding_data["device_kind"],
                    now=ding_data["now"],
                    expires_in=ding_data["expires_in"],
                    kind=ding_data["kind"],
                    state=ding_data["state"],
                )
                key = (re.doorbot_id, re.id, re.kind)
                if key not in alerts or re.now > alerts[key].now:
                    alerts[key] = re

        return alerts.values()
