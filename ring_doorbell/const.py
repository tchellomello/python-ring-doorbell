# vim:sw=4:ts=4:et:
"""Constants."""


class OAuth:
    """OAuth class constants"""

    ENDPOINT = "https://oauth.ring.com/oauth/token"
    CLIENT_ID = "ring_official_android"
    SCOPE = ["client"]


PACKAGE_NAME = "ring_doorbell"
# timeout for HTTP requests
TIMEOUT = 10

# longer default timeout for recording downloads - typical video file sizes
# are ~12 MB and empirical testing reveals a ~20 second download time over a
# fast connection, suggesting speed is largely governed by capacity of Ring
# backend; to be safe, we factor in a worst case overhead and set it to 2
# minutes (this default can be overridden in method call)
DEFAULT_VIDEO_DOWNLOAD_TIMEOUT = 120


# API endpoints
API_VERSION = "11"
API_URI = "https://api.ring.com"
USER_AGENT = "android:com.ringapp"

# random uuid, used to make a hardware id that doesn't change or clash
NAMESPACE_UUID = "379378b0-f747-4b67-a10f-3b13327e8879"

DEFAULT_LISTEN_EVENT_EXPIRES_IN = 180
# for Ring android app.  703521446232 for ring-site
RING_SENDER_ID = 876313859327

CLI_TOKEN_FILE = "ring_token.cache"  # noqa: S105
CHIMES_ENDPOINT = "/clients_api/chimes/{0}"
DEVICES_ENDPOINT = "/clients_api/ring_devices"
DINGS_ENDPOINT = "/clients_api/dings/active"
DOORBELLS_ENDPOINT = "/clients_api/doorbots/{0}"
PERSIST_TOKEN_ENDPOINT = "/clients_api/device"  # noqa: S105
SUBSCRIPTION_ENDPOINT = "/clients_api/device"
GROUPS_ENDPOINT = "/groups/v1/locations/{0}/groups"
LOCATIONS_HISTORY_ENDPOINT = "/evm/v2/history/locations/{0}"
LOCATIONS_ENDPOINT = "/clients_api/locations/{0}"

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
SETTINGS_ENDPOINT = "/devices/v1/devices/{0}/settings"
# Alternative API for Intercom history, not used in favor of the DoorBell API
URL_INTERCOM_HISTORY = LOCATIONS_HISTORY_ENDPOINT + "?ringtercom"
INTERCOM_OPEN_ENDPOINT = "/commands/v1/devices/{0}/device_rpc"
INTERCOM_INVITATIONS_ENDPOINT = LOCATIONS_ENDPOINT + "/invitations"
INTERCOM_INVITATIONS_DELETE_ENDPOINT = LOCATIONS_ENDPOINT + "/invitations/{1}"
INTERCOM_ALLOWED_USERS = LOCATIONS_ENDPOINT + "/users"

# New API endpoints for web rtc streaming
RTC_STREAMING_TICKET_ENDPOINT = "/api/v1/clap/ticket/request/signalsocket"
RTC_STREAMING_WEB_SOCKET_ENDPOINT = "wss://api.prod.signalling.ring.devices.a2z.com:443/ws?api_version=4.0&auth_type=ring_solutions&client_id=ring_site-{0}&token={1}"

KIND_DING = "ding"
KIND_MOTION = "motion"
KIND_INTERCOM_UNLOCK = "intercom_unlock"
# chime test sound kinds
CHIME_TEST_SOUND_KINDS = (KIND_DING, KIND_MOTION)

# default values
CHIME_VOL_MIN = 0
CHIME_VOL_MAX = 10

DOORBELL_VOL_MIN = 0
DOORBELL_VOL_MAX = 11

MIC_VOL_MIN = 0
MIC_VOL_MAX = 11

VOICE_VOL_MIN = 0
VOICE_VOL_MAX = 11

OTHER_DOORBELL_VOL_MIN = 0
OTHER_DOORBELL_VOL_MAX = 8

DOORBELL_EXISTING_TYPE = {0: "Mechanical", 1: "Digital", 2: "Not Present"}

SIREN_DURATION_MIN = 0
SIREN_DURATION_MAX = 120

# device model kinds
CHIME_KINDS = ["chime", "chime_v2"]
CHIME_PRO_KINDS = ["chime_pro", "chime_pro_v2"]

DOORBELL_KINDS = ["doorbot", "doorbell", "doorbell_v3"]
DOORBELL_2_KINDS = ["doorbell_v4", "doorbell_v5"]
DOORBELL_3_KINDS = ["doorbell_scallop_lite"]
DOORBELL_4_KINDS = ["doorbell_oyster"]  # Added
DOORBELL_3_PLUS_KINDS = ["doorbell_scallop"]
DOORBELL_PRO_KINDS = ["lpd_v1", "lpd_v2", "lpd_v3"]
DOORBELL_PRO_2_KINDS = ["lpd_v4"]
DOORBELL_ELITE_KINDS = ["jbox_v1"]
DOORBELL_WIRED_KINDS = ["doorbell_graham_cracker"]
PEEPHOLE_CAM_KINDS = ["doorbell_portal"]
DOORBELL_GEN2_KINDS = ["cocoa_doorbell", "cocoa_doorbell_v2"]

FLOODLIGHT_CAM_KINDS = ["hp_cam_v1", "floodlight_v2"]
FLOODLIGHT_CAM_PRO_KINDS = ["floodlight_pro"]
FLOODLIGHT_CAM_PLUS_KINDS = ["cocoa_floodlight"]
INDOOR_CAM_KINDS = ["stickup_cam_mini"]
INDOOR_CAM_GEN2_KINDS = ["stickup_cam_mini_v2"]
SPOTLIGHT_CAM_BATTERY_KINDS = ["stickup_cam_v4"]
SPOTLIGHT_CAM_WIRED_KINDS = ["hp_cam_v2", "spotlightw_v2"]
SPOTLIGHT_CAM_PLUS_KINDS = ["cocoa_spotlight"]
SPOTLIGHT_CAM_PRO_KINDS = ["stickup_cam_longfin"]
STICKUP_CAM_KINDS = ["stickup_cam", "stickup_cam_v3"]
STICKUP_CAM_BATTERY_KINDS = ["stickup_cam_lunar"]
STICKUP_CAM_ELITE_KINDS = ["stickup_cam_elite", "stickup_cam_wired"]
STICKUP_CAM_WIRED_KINDS = STICKUP_CAM_ELITE_KINDS  # Deprecated
STICKUP_CAM_GEN3_KINDS = ["cocoa_camera"]
BEAM_KINDS = ["beams_ct200_transformer"]

INTERCOM_KINDS = ["intercom_handset_audio"]

# error strings
MSG_BOOLEAN_REQUIRED = "Boolean value is required."
MSG_EXISTING_TYPE = f"Integer value where {DOORBELL_EXISTING_TYPE}."
MSG_GENERIC_FAIL = "Sorry.. Something went wrong..."
FILE_EXISTS = "The file {0} already exists."
MSG_VOL_OUTBOUND = "Must be within the {0}-{1}."
MSG_ALLOWED_VALUES = "Only the following values are allowed: {0}."
MSG_EXPECTED_ATTRIBUTE_NOT_FOUND = "Couldn't find expected attribute: {0}."

PUSH_ACTION_DING = "com.ring.push.HANDLE_NEW_DING"
PUSH_ACTION_MOTION = "com.ring.push.HANDLE_NEW_motion"
PUSH_ACTION_INTERCOM_UNLOCK = "com.ring.push.INTERCOM_UNLOCK_FROM_APP"

POST_DATA_JSON = {
    "api_version": API_VERSION,
    "device_model": "ring-doorbell",
}

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

ICE_SERVERS = [
    "stun:stun.kinesisvideo.us-east-1.amazonaws.com:443",
    "stun:stun.kinesisvideo.us-east-2.amazonaws.com:443",
    "stun:stun.kinesisvideo.us-west-2.amazonaws.com:443",
    "stun:stun.l.google.com:19302",
    "stun:stun1.l.google.com:19302",
    "stun:stun2.l.google.com:19302",
    "stun:stun3.l.google.com:19302",
    "stun:stun4.l.google.com:19302",
]
