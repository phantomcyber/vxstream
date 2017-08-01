# VxPhantom
The VxStream Sandbox Phantom App

Copyright (C) 2017 Payload Security UG (haftungsbeschränkt)
============

## Requirements

- [Phantom](https://phantom.us) >= 2.0.291

Installing the App in Phantom
---

#### For Phantom 2.0.

- [App Management](https://my.phantom.us/2.0/docs/admin/apps)
- [Assets Management](https://my.phantom.us/2.0/docs/admin/assets)

#### For Phantom 2.1.

- [App and Assets Management](https://my.phantom.us/2.1/docs/admin/apps_assets)

## Final Notes

Testing connectivity
---

After creating the VxStream Sandbox asset, we recommended to test the application server connectivity. That way,
you make sure that the provided base URL and API credentials are working correctly.

Creating a new tarball installation file (developers only)
---

1. Go to `VxPhantom` directory,
2. Run `python -m compileall .` command to prepare .pyc files (you can remove already existing .pyc files `find . -type f -name '*.pyc' -delete`),
3. Run `python compile_app.py -d -t` command.

