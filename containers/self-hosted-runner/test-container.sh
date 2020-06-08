# This command assumes GITHUB_REPOSITORY, GITHUB_REF, and GITHUB_SHA are set on
# the host.

podman run --rm \
--env GITHUB_REPOSITORY=${GITHUB_REPOSITORY} \
--env GITHUB_REF=${GITHUB_REF} \
--env GITHUB_SHA=${GITHUB_SHA} \
localhost/fedora-test-runner:latest
