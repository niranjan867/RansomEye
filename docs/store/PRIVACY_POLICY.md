# RansomEye Privacy Policy

**Effective Date:** October 27, 2026

## Overview

RansomEye is a digital forensics and incident response (DFIR) desktop application for Windows. It operates entirely on your local machine.

## Data Collection

RansomEye does **not** collect, transmit, store, or share any personal data, usage data, telemetry, analytics, or crash reports. The application makes no network connections to external servers for any purpose.

## Local Data Storage

All forensic evidence, case files, analysis results, and reports are stored locally on your device in a SQLite database and local files. This data never leaves your machine unless you manually export and share it.

## Network Activity

RansomEye performs no outbound network requests. The only network-related functionality is:

- **PCAP Analysis:** RansomEye can read and analyze network capture files (PCAP) that you provide. It does not capture network traffic itself.
- **Local Dashboard:** RansomEye runs a local web server bound to `127.0.0.1` (localhost only) for the analyst dashboard. This server is not accessible from other machines on the network.

## Third-Party Services

RansomEye does not integrate with, send data to, or receive data from any third-party services, advertising networks, or analytics platforms.

## Children's Privacy

RansomEye does not collect any data from any users, including children.

## Changes to This Policy

If this privacy policy changes, the updated version will be published at this same location with a new effective date.

## Contact

For questions about this privacy policy, please open an issue at:
https://github.com/niranjan867/RansomEye/issues
