# TLS trust anchors for the Redsim stack

This directory holds extra root certificates the build context needs to
trust when pulling base images and dependencies through a corporate
proxy (Zscaler).

## Files

- `zscaler.pem` — Zscaler Root CA, copied from the operator's machine
  (e.g. `~/Desktop/Zscaler Root CA.pem` on macOS, or the equivalent
  keychain export). Required for `pip install`, `npm install`, and
  GitHub / image-registry HTTPS calls inside the build.

If this directory is empty the Dockerfiles fall back to the distro's
stock CA bundle, which works on uncorporate networks but fails behind
Zscaler with `SSL_ERROR_RX_RECORD_TOO_LONG` / `unable to get local
issuer certificate`.

## Host-side env vars (for local pip / pytest / npm)

```bash
export REQUESTS_CA_BUNDLE=$PWD/deploy/certs/zscaler.pem
export SSL_CERT_FILE=$REQUESTS_CA_BUNDLE
export PIP_CERT=$REQUESTS_CA_BUNDLE
export NODE_EXTRA_CA_CERTS=$REQUESTS_CA_BUNDLE
```

Rotate by replacing `zscaler.pem` and rebuilding the images.
