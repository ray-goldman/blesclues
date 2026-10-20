# Signed software updates

The dashboard accepts signed updates from an HTTPS release feed or a local bundle upload. The feed needs an internet connection; the upload works while the Pi is offline. Both paths verify the Ed25519 signature, bundle size, archive paths, version, and SHA-256 checksums.

Checking and staging do not install a release. To install one, review its version and notes, then choose **Apply** and confirm. The updater keeps the previous release slot and restores it if the health check fails. Configuration and SQLite history stay under `/etc` and `/var/lib`, outside the release slots.

## Trust key and release signing

Create an Ed25519 key pair outside the repository. Keep the private key in a controlled signing environment; never copy it to the Pi or include it in a release bundle. Install the public key at `/etc/bt-signature-detector-trust/update.pub`, owned by `root:root` and mode `0644`. The trust directory must remain `root:root` mode `0755`; do not put the key under `/etc/bt-signature-detector`, which is writable by the web service group. The web interface cannot change this trust key.

For a new install, the installer can provision the key from a local file with `UPDATE_PUBLIC_KEY=/path/to/update.pub sudo -E bash scripts/install.sh`. To upgrade an existing install, first verify the old key against the fingerprint distributed through a trusted channel, then copy it into the protected directory:

```sh
sudo install -d -o root -g root -m 0755 /etc/bt-signature-detector-trust
sudo install -o root -g root -m 0644 /path/to/verified-update.pub /etc/bt-signature-detector-trust/update.pub
```

Do not automatically migrate `/etc/bt-signature-detector/update.pub`: its parent directory is writable by the web service group, so its contents cannot be trusted during migration.

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

The package tool creates a ZIP containing `manifest.json`, detached `manifest.sig`, and `artifact.whl`. Publish the exact `manifest.json` at the configured feed URL, its raw signature at the same URL with `.sig` appended, and the ZIP at the manifest's `artifact_url`. Keep the signing key out of source control and off the Pi.

## Install from the dashboard

For feed delivery, set `updates.manifest_url` in `/etc/bt-signature-detector/detector.yaml` and install the root-owned public key at `/etc/bt-signature-detector-trust/update.pub`. Connect the Pi to an uplink, open **Updates**, check the feed, and stage the verified build. For offline delivery, upload the ZIP bundle from **Updates**. Review the version and notes, then select **Apply** and confirm the restart.

The updater copies the current virtual environment into a versioned slot and installs the verified wheel without fetching dependencies. Build releases against the dependencies already installed on the Pi. Plan dependency changes as a separate maintenance operation. If the health check fails, the updater restores the previous active release; updating does not write configuration or detection history.

Without an internet connection, feed checks fail but scanning continues; signed local uploads remain available. The updater rejects unsigned or modified bundles before staging. Keep a known-good release and the root-owned public key available for recovery.
