=====================
Python Ring Door Bell
=====================

.. image:: https://badge.fury.io/py/ring-doorbell.svg
    :alt: PyPI Version
    :target: https://badge.fury.io/py/ring-doorbell

.. image:: https://github.com/tchellomello/python-ring-doorbell/actions/workflows/ci.yml/badge.svg?branch=master
    :alt: Build Status
    :target: https://github.com/tchellomello/python-ring-doorbell/actions/workflows/ci.yml?branch=master

.. image:: https://coveralls.io/repos/github/tchellomello/python-ring-doorbell/badge.svg?branch=master
    :alt: Coverage
    :target: https://coveralls.io/github/tchellomello/python-ring-doorbell?branch=master

.. image:: https://readthedocs.org/projects/python-ring-doorbell/badge/?version=latest
    :alt: Documentation Status
    :target: https://python-ring-doorbell.readthedocs.io/?badge=latest

.. image:: https://img.shields.io/pypi/pyversions/ring-doorbell.svg
    :alt: Py Versions
    :target: https://pypi.python.org/pypi/ring-doorbell


Python Ring Door Bell is a library written for Python 3.8+
that exposes the Ring.com devices as Python objects.

There is also a command line interface that is work in progress. `Contributors welcome <https://python-ring-doorbell.readthedocs.io/contributing.html>`_.

*Currently Ring.com does not provide an official API. The results of this project are merely from reverse engineering.*

Documentation: `http://python-ring-doorbell.readthedocs.io/ <http://python-ring-doorbell.readthedocs.io/>`_


Installation
------------

.. code-block:: bash

    # Installing from PyPi
    $ pip install ring_doorbell

    # Installing latest development
    $ pip install \
        git+https://github.com/tchellomello/python-ring-doorbell@master

Event Listener
++++++++++++++

If you want the ring api to listen for push events from ring.com for dings and motion you
will need to install with the `listen` extra::

    $ pip install ring_doorbell[listen]

The api will then start listening for push events after you have first called `update_dings()` 
or `update_data()` but only if there is a running `asyncio <https://docs.python.org/3/library/asyncio.html>`_ event loop (which there will be if using the CLI)

Using the CLI
-------------

The CLI is work in progress and currently has the following commands:

1.  Show your devices::
    
    $ ring-doorbell

    Or::

    $ ring-doorbell show

#.  List your device names (with device kind)::
    
    $ ring-doorbell list

#.  Either count or download your vidoes or both::

    $ ring-doorbell videos --count --download-all

#.  Enable disable motion detection::

    $ ring-doorbell motion-detection --device-name "DEVICENAME" --on
    $ ring-doorbell motion-detection --device-name "DEVICENAME" --off

#.  Listen for push notifications like the ones sent to your phone::

    $ ring-doorbell listen

#.  List your ring groups::

    $ ring-doorbell groups

#.  Show your ding history::

    $ ring-doorbell history --device-name "Front Door"

#.  Show your currently active dings::

    $ ring-doorbell dings

#.  Query a ring api url directly::

    $ ring-doorbell raw-query --url /clients_api/dings/active

#.  Run ``ring-doorbell --help`` or ``ring-doorbell videos --help`` for full options

Using the API
-------------

The API has an async interface and a sync interface.  All api calls starting `async` are
asynchronous.  This is the preferred method of interacting with the ring api and the sync
versions are maintained for backwards compatability.

*You cannot mix sync and async code*

Initializing your Ring object
+++++++++++++++++++++++++++++

This code example is in the `test.py <test.py>`_ file.  For a sync example see `test_sync.py <test_sync.py>`_.

.. code-block:: python

    import getpass
    import asyncio
    import json
    from pathlib import Path

    from ring_doorbell import Auth, AuthenticationError, Requires2FAError, Ring

    user_agent = "YourProjectName-1.0"  # Change this
    cache_file = Path(user_agent + ".token.cache")


    def token_updated(token):
        cache_file.write_text(json.dumps(token))


    def otp_callback():
        auth_code = input("2FA code: ")
        return auth_code


    async def do_auth():
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        auth = Auth(user_agent, None, token_updated)
        try:
            await auth.async_fetch_token(username, password)
        except Requires2FAError:
            await auth.async_fetch_token(username, password, otp_callback())
        return auth


    async def main():
        if cache_file.is_file():  # auth token is cached
            auth = Auth(user_agent, json.loads(cache_file.read_text()), token_updated)
            ring = Ring(auth)
            try:
                await ring.async_create_session()  # auth token still valid
            except AuthenticationError:  # auth token has expired
                auth = await do_auth()
        else:
            auth = await do_auth()  # Get new auth token
            ring = Ring(auth)

        await ring.async_update_data()

        devices = ring.devices()
<<<<<<< HEAD
        print(devices)
=======
        pprint(devices.devices_combined)
        await auth.async_close()
>>>>>>> 4796d3a (Make library fully async)


    if __name__ == "__main__":
        asyncio.run(main())



Listing devices linked to your account
++++++++++++++++++++++++++++++++++++++
.. code-block:: python

    # All devices
    devices = ring.devices()
    {'chimes': [<RingChime: Downstairs>],
    'doorbots': [<RingDoorBell: Front Door>]}

    # All doorbells
    doorbells = devices['doorbots']
    [<RingDoorBell: Front Door>]

    # All chimes
    chimes = devices['chimes']
    [<RingChime: Downstairs>]

    # All stickup cams
    stickup_cams = devices['stickup_cams']
    [<RingStickUpCam: Driveway>]

Playing with the attributes and functions
+++++++++++++++++++++++++++++++++++++++++
.. code-block:: python

    devices = ring.devices()
    for dev in list(devices['stickup_cams'] + devices['chimes'] + devices['doorbots']):
        await dev.async_update_health_data()
        print('Address:    %s' % dev.address)
        print('Family:     %s' % dev.family)
        print('ID:         %s' % dev.id)
        print('Name:       %s' % dev.name)
        print('Timezone:   %s' % dev.timezone)
        print('Wifi Name:  %s' % dev.wifi_name)
        print('Wifi RSSI:  %s' % dev.wifi_signal_strength)

        # setting dev volume
        print('Volume:     %s' % dev.volume)
        await dev.async_set_volume(5)
        print('Volume:     %s' % dev.volume)

        # play dev test shound
        if dev.family == 'chimes':
            await dev.async_test_sound(kind = 'ding')
            await dev.async_test_sound(kind = 'motion')

        # turn on lights on floodlight cam
        if dev.family == 'stickup_cams' and dev.lights:
            await dev.async_lights('on')


Showing door bell events
++++++++++++++++++++++++
.. code-block:: python

    devices = ring.devices()
    for doorbell in devices['doorbots']:

        # listing the last 15 events of any kind
        for event in await doorbell.async_history(limit=15):
            print('ID:       %s' % event['id'])
            print('Kind:     %s' % event['kind'])
            print('Answered: %s' % event['answered'])
            print('When:     %s' % event['created_at'])
            print('--' * 50)

        # get a event list only the triggered by motion
        events = await doorbell.async_history(kind='motion')


Downloading the last video triggered by a ding or motion event
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
.. code-block:: python

    devices = ring.devices()
    doorbell = devices['doorbots'][0]
    await doorbell.async_recording_download(
        await doorbell.async_history(limit=100, kind='ding')[0]['id'],
                         filename='last_ding.mp4',
                         override=True)


Displaying the last video capture URL
+++++++++++++++++++++++++++++++++++++
.. code-block:: python

    print(await doorbell.async_recording_url(await doorbell.async_last_recording_id()))
    'https://ring-transcoded-videos.s3.amazonaws.com/99999999.mp4?X-Amz-Expires=3600&X-Amz-Date=20170313T232537Z&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=TOKEN_SECRET/us-east-1/s3/aws4_request&X-Amz-SignedHeaders=host&X-Amz-Signature=secret'

Controlling a Light Group
+++++++++++++++++++++++++
.. code-block:: python

    groups = ring.groups()
    group = groups['the-group-you-want']

    print(group.lights)
    # Prints True if lights are on, False if off

    # Turn on lights indefinitely
    await group.async_set_lights(True)

    # Turn off lights
    await group.async_set_lights(False)

    # Turn on lights for 30 seconds
    await group.async_set_lights(True, 30)

How to contribute
-----------------
See our `Contributing Page <https://python-ring-doorbell.readthedocs.io/contributing.html>`_.


Credits && Thanks
-----------------

* This project was inspired and based on https://github.com/jeroenmoors/php-ring-api. Many thanks @jeroenmoors.
* A guy named MadBagger at Prism19 for his initial research (http://www.prism19.com/doorbot/second-pass-and-comm-reversing/)
* The creators of mitmproxy (https://mitmproxy.org/) great http and https traffic inspector
* @mfussenegger for his post on mitmproxy and virtualbox https://zignar.net/2015/12/31/sniffing-vbox-traffic-mitmproxy/
* To the project http://www.android-x86.org/ which allowed me to install Android on KVM.
* Many thanks to Carles Pina I Estany <carles@pina.cat> for creating the python-ring-doorbell Debian Package (https://tracker.debian.org/pkg/python-ring-doorbell). 
