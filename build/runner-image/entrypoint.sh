#!/bin/sh
# Optional shell entrypoint — the Dockerfile uses the binary's ENTRYPOINT
# directly, so this script is intentionally unused in the published image.
# It exists for ad-hoc debugging: `docker run --rm -it --entrypoint /bin/sh ...`
# users can `sh entrypoint.sh /tmp/spec.json` to drive the runner manually.
exec /quokka agent run --job-file "${1:-/job/spec.json}"
