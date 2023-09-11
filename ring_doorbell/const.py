# coding: utf-8
# vim:sw=4:ts=4:et:
"""Constants."""


class OAuth:
    """OAuth class constants"""

    ENDPOINT = "https://oauth.ring.com/oauth/token"
    CLIENT_ID = "ring_official_android"
    SCOPE = ["client"]


# timeout for HTTP requests
TIMEOUT = 10

# longer default timeout for recording downloads - typical video file sizes
# are ~12 MB and empirical testing reveals a ~20 second download time over a
# fast connection, suggesting speed is largely governed by capacity of Ring
# backend; to be safe, we factor in a worst case overhead and set it to 2
# minutes (this default can be overridden in method call)
DEFAULT_VIDEO_DOWNLOAD_TIMEOUT = 120


# API endpoints
API_VERSION = "9"
API_URI = "https://api.ring.com"
CHIMES_ENDPOINT = "/clients_api/chimes/{0}"
DEVICES_ENDPOINT = "/clients_api/ring_devices"
DINGS_ENDPOINT = "/clients_api/dings/active"
DOORBELLS_ENDPOINT = "/clients_api/doorbots/{0}"
PERSIST_TOKEN_ENDPOINT = "/clients_api/device"
GROUPS_ENDPOINT = "/groups/v1/locations/{0}/groups"

HEALTH_DOORBELL_ENDPOINT = DOORBELLS_ENDPOINT + "/health"
HEALTH_CHIMES_ENDPOINT = CHIMES_ENDPOINT + "/health"
LIGHTS_ENDPOINT = DOORBELLS_ENDPOINT + "/floodlight_light_{1}"
LINKED_CHIMES_ENDPOINT = CHIMES_ENDPOINT + "/linked_doorbots"
LIVE_STREAMING_ENDPOINT = DOORBELLS_ENDPOINT + "/live_view"
NEW_SESSION_ENDPOINT = "/clients_api/session"
RINGTONES_ENDPOINT = "/ringtones"
SIREN_ENDPOINT = DOORBELLS_ENDPOINT + "/siren_{1}"
SNAPSHOT_ENDPOINT = "/clients_api/snapshots/image/{0}"
SNAPSHOT_TIMESTAMP_ENDPOINT = "/clients_api/snapshots/timestamps"
TESTSOUND_CHIME_ENDPOINT = CHIMES_ENDPOINT + "/play_sound"
URL_DOORBELL_HISTORY = DOORBELLS_ENDPOINT + "/history"
URL_RECORDING = "/clients_api/dings/{0}/recording"
URL_RECORDING_SHARE_PLAY = "/clients_api/dings/{0}/share/play"
GROUP_DEVICES_ENDPOINT = GROUPS_ENDPOINT + "/{1}/devices"
DO_NOT_DISTURB_CHIME_ENDPOINT = CHIMES_ENDPOINT + "/do_not_disturb"

# chime test sound kinds
KIND_DING = "ding"
KIND_MOTION = "motion"
CHIME_TEST_SOUND_KINDS = (KIND_DING, KIND_MOTION)

# default values
CHIME_VOL_MIN = 0
CHIME_VOL_MAX = 10

DOORBELL_VOL_MIN = 0
DOORBELL_VOL_MAX = 11

DOORBELL_EXISTING_TYPE = {0: "Mechanical", 1: "Digital", 2: "Not Present"}

SIREN_DURATION_MIN = 0
SIREN_DURATION_MAX = 120

# device model kinds
CHIME_KINDS = ["chime", "chime_v2"]
CHIME_PRO_KINDS = ["chime_pro", "chime_pro_v2"]

DOORBELL_KINDS = ["doorbot", "doorbell", "doorbell_v3", "cocoa_doorbell"]
DOORBELL_2_KINDS = ["doorbell_v4", "doorbell_v5"]
DOORBELL_3_KINDS = ["doorbell_scallop_lite"]
DOORBELL_3_PLUS_KINDS = ["doorbell_scallop"]
DOORBELL_PRO_KINDS = ["lpd_v1", "lpd_v2", "lpd_v4"]
DOORBELL_ELITE_KINDS = ["jbox_v1"]
PEEPHOLE_CAM_KINDS = ["doorbell_portal"]

FLOODLIGHT_CAM_KINDS = ["hp_cam_v1", "floodlight_v2", "cocoa_floodlight"]
FLOODLIGHT_CAM_PRO_KINDS = ["floodlight_pro"]
INDOOR_CAM_KINDS = ["stickup_cam_mini"]
SPOTLIGHT_CAM_BATTERY_KINDS = ["stickup_cam_v4"]
SPOTLIGHT_CAM_WIRED_KINDS = ["hp_cam_v2", "spotlightw_v2"]
STICKUP_CAM_KINDS = ["stickup_cam", "stickup_cam_v3"]
STICKUP_CAM_BATTERY_KINDS = ["cocoa_camera", "stickup_cam_lunar"]
STICKUP_CAM_WIRED_KINDS = ["stickup_cam_elite"]
BEAM_KINDS = ["beams_ct200_transformer"]

# error strings
MSG_BOOLEAN_REQUIRED = "Boolean value is required."
MSG_EXISTING_TYPE = "Integer value where {0}.".format(DOORBELL_EXISTING_TYPE)
MSG_GENERIC_FAIL = "Sorry.. Something went wrong..."
FILE_EXISTS = "The file {0} already exists."
MSG_VOL_OUTBOUND = "Must be within the {0}-{1}."
MSG_ALLOWED_VALUES = "Only the following values are allowed: {0}."

POST_DATA = {
    "api_version": API_VERSION,
    "device[os]": "android",
    "device[app_brand]": "ring",
    "device[metadata][device_model]": "KVM",
    "device[metadata][device_name]": "Python",
    "device[metadata][resolution]": "600x800",
    "device[metadata][app_version]": "1.3.806",
    "device[metadata][app_instalation_date]": "",
    "device[metadata][manufacturer]": "Qemu",
    "device[metadata][device_type]": "desktop",
    "device[metadata][architecture]": "desktop",
    "device[metadata][language]": "en",
}

PERSIST_TOKEN_DATA = {
    "api_version": API_VERSION,
    "device[metadata][device_model]": "KVM",
    "device[metadata][device_name]": "Python",
    "device[metadata][resolution]": "600x800",
    "device[metadata][app_version]": "1.3.806",
    "device[metadata][app_instalation_date]": "",
    "device[metadata][manufacturer]": "Qemu",
    "device[metadata][device_type]": "desktop",
    "device[metadata][architecture]": "x86",
    "device[metadata][language]": "en",
}
