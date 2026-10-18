# Signed software updates

The dashboard supports two manual update sources: an HTTPS release feed when Ethernet or another uplink is available, and a local signed bundle upload when the Pi is offline. Both use the same Ed25519 signature, bundle-size, archive-path, version, and SHA-256 checks. Checking or staging never installs a release; applying requires a separate confirmation and restarts the scanner. The updater keeps the prior release slot and restores it if the health check fails. Configuration and SQLite history stay under `/etc` and `/var/lib`, outside release slots.

## Trust key and release signing

Create an Ed25519 key pair outside the repository. Protect the private key in a controlled signing environment; never copy it to the Pi or into a release bundle. Install only the public key as `/etc/bt-signature-detector/update.pub`, owned by root and readable by the detector group (for example mode `0640`). The web interface cannot change the trust key.

Build a wheel, then package it with release notes, a semantic version, the external private key, and the public HTTPS URL where the signed bundle will be published:

```sh
python -m pip wheel --no-deps --wheel-dir dist .
python scripts/package_release.py \
  --wheel dist/bt_signature_detector-0.1.0-py3-none-any.whl \
  --notes release-notes.txt --version 0.1.0 \
  --private-key /secure/offline/release-ed25519.pem \
  --artifact-url https://releases.example.org/bt-detector-0.1.0.zip \
  --output dist/bt-detector-0.1.0.zip
```

The package tool emits a ZIP containing `manifest.json`, detached `manifest.sig`, and `artifact.whl`. Publish the same canonical `manifest.json` at the configured feed URL, its raw signature at that URL plus `.sig`, and the ZIP at the manifest's `artifact_url`. Keep the signing key outside source control and the Pi.

## Install from the dashboard

For HTTPS delivery, set `updates.manifest_url` in `/etc/bt-signature-detector/detector.yaml` to the HTTPS manifest URL and install the root-owned public key. Connect Ethernet, open **Software updates**, check the feed, and stage the verified build. For offline delivery, upload the ZIP bundle from **Software updates**. After reviewing the version and notes, select **Apply** and confirm the restart.

The updater copies the current virtual environment into a version slot and installs the verified wheel without fetching dependencies. Release builds should remain compatible with the dependencies in the installed environment. If a dependency change is needed, deliver and validate that as a separately planned maintenance operation. A failed health check restores the old active release; update attempts never write configuration or detection history.

If Ethernet is unavailable, feed checks fail without affecting scanning; local signed uploads remain available. Unsigned or modified bundles are rejected before staging. Keep a known-good release and the root-owned public key available for recovery.
