# vim:sw=4:ts=4:et
# Many thanks to @troopermax <https://github.com/troopermax>
"""Python Ring command line interface."""

from __future__ import annotations

import asyncio
import functools
import getpass
import json
import logging
import select
import sys
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path, PurePath
from typing import Sequence, cast

import asyncclick as click

from ring_doorbell import (
    Auth,
    AuthenticationError,
    Requires2FAError,
    Ring,
    RingDoorBell,
    RingEvent,
    RingGeneric,
)
from ring_doorbell.const import CLI_TOKEN_FILE, GCM_TOKEN_FILE, PACKAGE_NAME, USER_AGENT
from ring_doorbell.listen import can_listen


def _header() -> None:
    _bar()
    echo("Ring CLI")


def _bar() -> None:
    echo("---------------------------------")


click.anyio_backend = "asyncio"  # type: ignore[attr-defined]

pass_ring = click.make_pass_decorator(Ring)

cache_file = Path(CLI_TOKEN_FILE)
gcm_cache_file = Path(GCM_TOKEN_FILE)


def CatchAllExceptions(cls):
    """Capture all exceptions and prints them nicely.

    Idea from https://stackoverflow.com/a/44347763 and
    https://stackoverflow.com/questions/52213375
    """

    def _handle_exception(debug, exc):
        if isinstance(exc, click.ClickException):
            raise
        echo(f"Raised error: {exc}")
        if debug:
            raise
        echo("Run with --debug enabled to see stacktrace")
        sys.exit(1)

    class _CommandCls(cls):
        _debug = False

        async def make_context(self, info_name, args, parent=None, **extra):
            self._debug = any(
                [arg for arg in args if arg in ["--debug", "-d", "--verbose", "-v"]]
            )
            try:
                return await super().make_context(
                    info_name, args, parent=parent, **extra
                )
            except Exception as exc:
                _handle_exception(self._debug, exc)

        async def invoke(self, ctx):
            try:
                return await super().invoke(ctx)
            except asyncio.CancelledError:
                pass
            except KeyboardInterrupt:
                echo("Cli interrupted with keyboard interrupt")
            except Exception as exc:
                _handle_exception(self._debug, exc)

    return _CommandCls


class MutuallyExclusiveOption(click.Option):
    """Prevents incompatable options being supplied, i.e. on and off."""

    def __init__(self, *args, **kwargs) -> None:
        self.mutually_exclusive = set(kwargs.pop("mutually_exclusive", []))
        _help = kwargs.get("help", "")
        if self.mutually_exclusive:
            ex_str = ", ".join(self.mutually_exclusive)
            kwargs["help"] = _help + (
                " NOTE: This argument is mutually exclusive with "
                " arguments: [" + ex_str + "]."
            )
        super().__init__(*args, **kwargs)

    async def handle_parse_result(self, ctx, opts, args):
        if self.mutually_exclusive.intersection(opts) and self.name in opts:
            msg = (
                "Illegal usage: `{}` is mutually exclusive with "
                "arguments `{}`.".format(self.name, ", ".join(self.mutually_exclusive))
            )
            raise click.UsageError(msg)

        return await super().handle_parse_result(ctx, opts, args)


echo = click.echo


def token_updated(token) -> None:
    """Writes token to file."""
    cache_file.write_text(json.dumps(token), encoding="utf-8")


def _format_filename(device_name, event):
    if not isinstance(event, dict):
        return None

    answered_status = "answered" if event["answered"] else "not_answered"

    filename = "{}_{}_{}_{}_{}".format(
        device_name, event["created_at"], event["kind"], answered_status, event["id"]
    )

    return filename.replace(" ", "_").replace(":", ".") + ".mp4"


async def _do_auth(username, password, user_agent=USER_AGENT):
    if not username:
        username = input("Username: ")

    if not password:
        password = getpass.getpass("Password: ")

    auth = Auth(user_agent, None, token_updated)
    try:
        await auth.async_fetch_token(username, password)
        return auth
    except Requires2FAError:
        await auth.async_fetch_token(username, password, input("2FA Code: "))
        return auth


async def _get_ring(username, password, do_update_data, user_agent=USER_AGENT):
    # connect to Ring account
    global cache_file, gcm_cache_file
    if user_agent != USER_AGENT:
        cache_file = Path(user_agent + ".token.cache")
        gcm_cache_file = Path(user_agent + ".gcm_token.cache")
    if cache_file.is_file():
        auth = Auth(
            user_agent,
            json.loads(cache_file.read_text(encoding="utf-8")),
            token_updated,
        )
        ring = Ring(auth)
        do_method = (
            ring.async_update_data if do_update_data else ring.async_create_session
        )
        try:
            await do_method()
        except AuthenticationError:
            auth = await _do_auth(username, password)
            ring = Ring(auth)
            do_method = (
                ring.async_update_data if do_update_data else ring.async_create_session
            )
            await do_method()
    else:
        auth = await _do_auth(username, password, user_agent=user_agent)
        ring = Ring(auth)
        do_method = (
            ring.async_update_data if do_update_data else ring.async_create_session
        )
        await do_method()

    return ring


@click.group(
    invoke_without_command=True,
    cls=CatchAllExceptions(click.Group),
)
@click.version_option(package_name="ring_doorbell")
@click.option(
    "--username",
    default=None,
    required=False,
    envvar="RING_USERNAME",
    help="Username for Ring account.",
)
@click.option(
    "--password",
    default=None,
    required=False,
    envvar="RING_PASSWORD",
    help="Password for Ring account",
)
@click.option("-d", "--debug", default=False, is_flag=True)
@click.option(
    "--user-agent",
    default=USER_AGENT,
    required=False,
    envvar="RING_USER_AGENT",
    help="User agent to send to ring",
)
@click.pass_context
async def cli(ctx, username, password, debug, user_agent):
    """Command line function."""
    _header()

    logging.basicConfig()
    log_level = logging.DEBUG if debug else logging.INFO
    logger = logging.getLogger(PACKAGE_NAME)
    logger.setLevel(log_level)
    if can_listen:
        logger = logging.getLogger("firebase_messaging")
        logger.setLevel(log_level)

    no_update_commands = ["listen"]
    no_update = ctx.invoked_subcommand in no_update_commands

    @asynccontextmanager
    async def async_wrapped_ring(ring: Ring):
        try:
            yield ring
        finally:
            await ring.auth.async_close()

    ring = await _get_ring(username, password, not no_update, user_agent)
    # wrapped ring will ensure async_close is called when cli is finished
    ctx.obj = await ctx.with_async_resource(async_wrapped_ring(ring))

    if ctx.invoked_subcommand is None:
        return await ctx.invoke(show)
    return None


@cli.command(name="list")
@pass_ring
async def list_command(ring: Ring) -> None:
    """List ring devices."""
    devices = ring.devices()
    device: RingGeneric | None = None
    for device in devices.doorbots:
        echo(device)
    for device in devices.authorized_doorbots:
        echo(device)
    for device in devices.chimes:
        echo(device)
    for device in devices.stickup_cams:
        echo(device)
    for device in devices.other:
        echo(device)


@cli.command()
@pass_ring
@click.pass_context
@click.option(
    "--on",
    "turn_on",
    cls=MutuallyExclusiveOption,
    is_flag=True,
    default=None,
    required=False,
    mutually_exclusive=["--off"],
)
@click.option(
    "--off",
    "turn_off",
    cls=MutuallyExclusiveOption,
    is_flag=True,
    default=None,
    required=False,
    mutually_exclusive=["--on"],
)
@click.option(
    "--device-name",
    "-dn",
    required=True,
    default=None,
    help="Name of the ring device",
)
async def motion_detection(ctx, ring: Ring, device_name, turn_on, turn_off):
    """Display ring devices."""
    device = ring.get_device_by_name(device_name)

    if not device:
        echo(
            f"No device with name {device_name} found."
            + " List of found device names (kind) is:"
        )
        return await ctx.invoke(list_command)
    if not device.has_capability("motion_detection"):
        echo(f"{device!s} is not capable of motion detection")
        return None
    device = cast(RingDoorBell, device)
    state = "on" if device.motion_detection else "off"
    if not turn_on and not turn_off:
        echo(f"{device!s} has motion detection {state}")
        return None
    is_on = device.motion_detection
    if (turn_on and is_on) or (turn_off and not is_on):
        echo(f"{device!s} already has motion detection {state}")
        return None

    await device.async_set_motion_detection(turn_on if turn_on else False)
    state = "on" if device.motion_detection else "off"
    echo(f"{device!s} motion detection set to {state}")
    return None


@cli.command()
@click.option(
    "--device-name",
    "-dn",
    required=False,
    default=None,
    help="Name of device, if ommited shows all devices",
)
@pass_ring
@click.pass_context
async def show(ctx, ring: Ring, device_name):
    """Display ring devices."""
    devices: Sequence[RingGeneric] | None = None

    if device_name and (device := ring.get_device_by_name(device_name)):
        devices = [device]
    elif device_name:
        echo(
            f"No device with name {device_name} found. "
            + "List of found device names (kind) is:"
        )
        return await ctx.invoke(list_command)
    else:
        devices = ring.get_device_list()

    for dev in devices:
        await dev.async_update_health_data()
        echo("Name:       %s" % dev.name)
        echo("Family:     %s" % dev.family)
        echo("ID:         %s" % dev.id)
        echo("Timezone:   %s" % dev.timezone)
        echo("Wifi Name:  %s" % dev.wifi_name)
        echo("Wifi RSSI:  %s" % dev.wifi_signal_strength)
        echo()
    return None


@cli.command(name="devices")
@click.option(
    "--device-name",
    "-dn",
    required=False,
    default=None,
    help="Name of device, if ommited shows all devices",
)
@click.option(
    "--json",
    "json_flag",
    required=False,
    is_flag=True,
    help="Output raw json",
)
@pass_ring
@click.pass_context
async def devices_command(ctx, ring: Ring, device_name, json_flag):
    """Get device information."""
    if not json_flag:
        echo(
            "(Pretty format coming soon, if you want json consistently "
            + "from this command provide the --json flag)"
        )
    device_json = None
    if device_name and (device := ring.get_device_by_name(device_name)):
        device_json = ring.devices_data[device.family][device.id]
    elif device_name:
        echo(
            f"No device with name {device_name} found. "
            + "List of found device names (kind) is:"
        )
        return await ctx.invoke(list_command)

    if device_json:
        echo(json.dumps(device_json, indent=2))
        return None
    else:
        for device_type in ring.devices_data:
            for device_api_id in ring.devices_data[device_type]:
                echo(
                    json.dumps(ring.devices_data[device_type][device_api_id], indent=2)
                )
        return None


@cli.command()
@click.option(
    "--json",
    "json_flag",
    required=False,
    is_flag=True,
    help="Output raw json",
)
@pass_ring
async def dings(ring: Ring, json_flag) -> None:
    """Get dings information."""
    if not json_flag:
        echo(
            "(Pretty format coming soon, if you want json consistently "
            + "from this command provide the --json flag)"
        )
    echo(json.dumps(ring.dings_data, indent=2))


@cli.command()
@click.option(
    "--json",
    "json_flag",
    required=False,
    is_flag=True,
    help="Output raw json",
)
@pass_ring
async def groups(ring: Ring, json_flag) -> None:
    """Get group information."""
    if not json_flag:
        echo(
            "(Pretty format coming soon, if you want json consistently "
            + "from this command provide the --json flag)"
        )
    if not ring.groups_data:
        echo("No ring device groups setup")
    else:
        for light_group in ring.groups().values():
            await light_group.async_update()
            echo(json.dumps(light_group._attrs, indent=2))
            echo(json.dumps(light_group._health_attrs, indent=2))


@cli.command()
@click.option(
    "--url",
    required=True,
    type=str,
    help="Url to query, i.e. /clients_api/dings/active",
)
@pass_ring
async def raw_query(ring: Ring, url) -> None:
    """Directly query a url and return json result."""
    resp = await ring.async_query(url)
    data = resp.json()
    echo(json.dumps(data, indent=2))


@cli.command(name="history")
@click.option(
    "--device-name",
    "-dn",
    required=False,
    default=None,
    help="Name of device, if ommited shows all devices",
)
@click.option(
    "--limit",
    required=False,
    default=5,
    help="Limit number of records to return",
)
@click.option(
    "--kind",
    required=False,
    default=None,
    type=click.Choice(["ding", "motion", "on_demand"], case_sensitive=False),
    help="Get devices",
)
@click.option(
    "--json",
    "json_flag",
    required=False,
    is_flag=True,
    help="Output raw json",
)
@pass_ring
@click.pass_context
async def history_command(ctx, ring: Ring, device_name, kind, limit, json_flag):
    """Print raw json."""
    if not json_flag:
        echo(
            "(Pretty format coming soon, if you want json consistently "
            + "from this command provide the --json flag)"
        )
    device = ring.get_device_by_name(device_name)
    if not device:
        echo(
            f"No device with name {device_name} found. "
            + "List of found device names (kind) is:"
        )
        return await ctx.invoke(list_command)

    history = await device.async_history(limit=limit, kind=kind, convert_timezone=False)
    echo(json.dumps(history, indent=2))
    return None


@cli.command()
@click.option(
    "--count",
    required=False,
    default=False,
    is_flag=True,
    help="Count the number of videos on your Ring account",
)
@click.option(
    "--download-all",
    required=False,
    default=False,
    is_flag=True,
    help="Download all videos on your Ring account",
)
@click.option(
    "--download",
    required=False,
    default=False,
    is_flag=True,
    help="Download videos on your Ring account up to the max-count option",
)
@click.option(
    "--max-count",
    required=False,
    default=300,
    help="Maximum count of videos to count or download from your Ring account",
)
@click.option(
    "--download-to",
    required=False,
    default="./",
    help="Download location ending with a /",
)
@click.option(
    "--device-name",
    "-dn",
    default=None,
    required=False,
    help="Name of the ring device, if ommited uses the first device returned",
)
@pass_ring
@click.pass_context
async def videos(
    ctx, ring: Ring, count, download, download_all, max_count, download_to, device_name
):
    """Interact with ring videos."""
    device = None
    if device_name and not (device := ring.get_video_device_by_name(device_name)):
        echo(
            f"No device with name {device_name} found. "
            + "List of found device names (kind) is:"
        )
        return await ctx.invoke(list_command)
    if device and not device.has_capability("video"):
        echo(f"Device {device.name} is not a video device")
        return None
    # return the first device is implemented to be consistent with previous cli version
    if not device:
        if video_devices := ring.video_devices():
            device = video_devices[0]
        else:
            echo(
                "No video devices found. "
                + "List of found device names (with device kind) is:"
            )
            return await ctx.invoke(list_command)

    if not device:  # Make mypy happy
        return None
    if (
        not count
        and not download
        and not download_all
        and device.last_recording_id
        and (url := await device.async_recording_url(device.last_recording_id))
    ):
        echo("Last recording url is: " + url)
        return None

    events = None
    if download_all:
        download = True
        max_count = -1

    async def _get_events(device, max_count):
        limit = 100 if max_count == -1 else min(100, max_count)
        events = []
        history = await device.async_history(limit=limit)
        while len(history) > 0:
            events += history
            if (len(events) >= max_count and max_count != -1) or len(history) < limit:
                break
            history = await device.async_history(
                older_than=history[-1]["id"], limit=limit
            )
        return events

    if count:
        echo(
            f"\tCounting videos linked on your Ring account for {device.name}.\n"
            + "\tThis may take some time....\n"
        )

        events = await _get_events(device, max_count)

        motion = len([m["kind"] for m in events if m["kind"] == "motion"])
        ding = len([m["kind"] for m in events if m["kind"] == "ding"])
        on_demand = len([m["kind"] for m in events if m["kind"] == "on_demand"])

        echo(f"\tTotal videos: {len(events)}")
        echo(f"\tDing triggered: {ding}")
        echo(f"\tMotion triggered: {motion}")
        echo(f"\tOn-Demand triggered: {on_demand}")

    if download:
        if events is None:
            echo(
                "\tGetting videos linked on your Ring account.\n"
                "\tThis may take some time....\n"
            )
            events = await _get_events(device, max_count)

        echo(
            f"\tDownloading {len(events)} videos linked on your Ring account.\n"
            "\tThis may take some time....\n"
        )
        for counter, event in enumerate(events):
            filename = str(PurePath(download_to, _format_filename(device.name, event)))
            echo(f"\t{counter}/{len(events)} Downloading {filename}")

            await device.async_recording_download(
                event["id"], filename=filename, override=False
            )
        return None
    return None


async def ainput(string: str):
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, lambda s=string: sys.stdout.write(s + " "))  # type: ignore[misc]

    def read_with_timeout(timeout):
        if select.select(
            [
                sys.stdin,
            ],
            [],
            [],
            timeout,
        )[0]:
            # line = sys.stdin.next()
            return sys.stdin.readline()
        return None

    line = None
    while loop.is_running() and not line:
        line = await loop.run_in_executor(None, functools.partial(read_with_timeout, 1))
    return line


def get_now_str():
    return str(datetime.utcnow())


class _event_handler:  # pylint:disable=invalid-name
    def __init__(self, ring: Ring) -> None:
        self.ring = ring

    def on_event(self, event: RingEvent) -> None:
        msg = (
            get_now_str()
            + ": "
            + str(event)
            + " : Currently active count = "
            + str(len(self.ring.push_dings_data))
        )
        echo(msg)


@cli.command
@click.option(
    "--credentials-file",
    required=False,
    default=None,
    help=(
        "File to store push credentials, "
        + "if not provided credentials will be recreated from scratch"
    ),
)
@click.option(
    "--store-credentials/--no-store-credentials",
    default=True,
    help="Whether or not to store the push credentials, default is false",
)
@click.option(
    "--show-credentials",
    default=False,
    is_flag=True,
    help="Whether or not to show the push credentials, default is false",
)
@pass_ring
@click.pass_context
async def listen(
    ctx,
    ring,
    store_credentials,
    credentials_file,
    show_credentials,
) -> None:
    """Listen to push notification like the ones sent to your phone."""
    if not can_listen:
        echo("Ring is not configured for listening to notifications!")
        echo("pip install ring_doorbell[listen]")
        return

    from ring_doorbell.listen import (  # pylint:disable=import-outside-toplevel
        RingEventListener,
    )

    def credentials_updated_callback(credentials) -> None:
        if store_credentials:
            with open(credentials_file, "w", encoding="utf-8") as f:
                json.dump(credentials, f)
        else:
            echo("New push credentials created:")
            if show_credentials:
                echo(credentials)

    if not credentials_file:
        credentials_file = gcm_cache_file
    else:
        credentials_file = Path(credentials_file)

    credentials = None
    if store_credentials and credentials_file.is_file():
        # already registered, load previous credentials
        with open(credentials_file, encoding="utf-8") as f:
            credentials = json.load(f)

    event_listener = RingEventListener(ring, credentials, credentials_updated_callback)
    await event_listener.async_start()
    event_listener.add_notification_callback(_event_handler(ring).on_event)

    await ainput("Listening, press enter to cancel\n")

    event_listener.stop()


if __name__ == "__main__":
    cli()  # pylint: disable=no-value-for-parameter
