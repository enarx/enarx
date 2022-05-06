#!/usr/bin/env bash

set -u
set -e
# set -x  # Uncomment to debug

#
# Constants
#

# The crates we plan on releasing
readonly CRATES=(sallyport enarx-shim-kvm enarx-shim-sgx enarx-exec-wasmtime enarx-exec-wasmtime-bin enarx)

# The enarx team-maintained dependencies we want to update
readonly DEPS=(crt0stack flagset iocuddle lset mmarinus mmledger nbytes noted primordial rcrt1 sgx vdso xsave)

# Constants for release testing container images
readonly IMAGE_PREFIX="registry.gitlab.com/enarx/misc-testing/"
readonly IMAGES=(ubuntu debian centos7 centos8 fedora)
readonly IMAGE_SUFFIX="-base:2022-05-06T04-13-41Z"

# E2E/Install documentation contexts used in docs/Install.md to test on container images (test plans)
readonly CONTEXTS=("crates,helloworld" "git,helloworld")

#
# Flags
#

readonly CLEANUP="${CLEANUP:-false}" # Delete cloned repo, mock registry and stop process repository after build
readonly CONFIRM="${CONFIRM:-true}"  # Should we confirm on each step (some steps cannot be skipped)
readonly DRYRUN="${DRYRUN:-true}"    # Do not make any external facing changes

# WARNING: could fail due to interdependencies of bindep crates
readonly DR_PUBLISH="${DR_PUBLISH:-false}" # Determines if we should do a crate dry-run publish

#
# Globals
#
export MOCK_ON="false"
export REPO_DIR=""
export REPO_PATH=""
export REGISTRY_PATH=""
export REGISTRY_PID=""
export MOCKED_REGISTRY=""
export CARGO_REGISTRIES_MOCKED_INDEX=""
export CARGO_REGISTRIES_MOCKED_TOKEN=""

#
# Initial setup
#

# install_prereqs() {
#     set +e
#     # Assuming rust/cargo, docker, git + gpg signing and the GitHub CLI is set up correctly
#     cargo install sd cargo-show ripgrep cargo-http-registry cargo-edit
#     set -e
# }

# Checks out a clean copy of the code from main branch of the enarx/enarx repository
checkout_repository() {
    local version="$1"
    REPO_DIR="$(realpath "$(mktemp -d --suffix='-repo')")"
    REPO_PATH="file://${REPO_DIR}"

    cd "$REPO_DIR"
    read -p "Provide git repository URL for user's fork: " -r FORK_URL
    git clone "$FORK_URL" .
    git remote add upstream https://github.com/enarx/enarx.git >/dev/null 2>&1
    git fetch --all --tags >/dev/null 2>&1
    git checkout -b "release/${version}" upstream/main >/dev/null 2>&1
    realpath "${REPO_DIR}"
}

# Sets up a mock registry for testing
setup_mock_registry() {
    REGISTRY_PATH="$(realpath "$(mktemp -d --suffix='-registry')")"
    MOCKED_REGISTRY="mocked"
    CARGO_REGISTRIES_MOCKED_INDEX="file://${REGISTRY_PATH}"
    CARGO_REGISTRIES_MOCKED_TOKEN="${MOCKED_REGISTRY}token"
    cargo-http-registry "${REGISTRY_PATH}" >/dev/null 2>&1 &
    REGISTRY_PID="$!"
}

#
# Code building
#

build() {
    time cargo build --release
    echo -e "\n\n\n"
    time cargo run --release info
    echo -e "\n\n\n"
    time cargo test
    echo -e "\n\n\n"
}

clean() {
    cargo clean
    cargo clean -r
    cargo fetch
}

#
# Version functions
#

get_version() {
    rg '^version = ' Cargo.toml | cut -d\" -f2
}

get_latest_crate_version() {
    local crate="$1"
    cargo show "${crate}" | rg max_version | cut -d ' ' -f2
}

get_rust_toolchain_version() {
    grep channel rust-toolchain.toml | cut -d \" -f 2
}

#
# Update versions
#

update_git_ref_to_crate() {
    for i in "${DEPS[@]}"; do
        latest_version="$(cargo show "$i" | rg max_version | cut -d ' ' -f2)"
        find . -name "Cargo.toml" -exec sd "^$i\s*=\s*\{\s*version\s*=\s*\"\d+\.\d+\.\d+\w*\"" "$i = { version = \"${latest_version}\"" {} \;
        find crates/ -name "Cargo.toml" -exec sd "$i\s*=\s*\{\s*git\s*=\s*\"https://github.com/enarx/$i\",\s*rev\s*=\s*\"\w+\"" "$i = { version = \"${latest_version}\"" {} \;
        sd "$i\s*=\s*\{\s*git\s*=\s*\"https://github.com/enarx/$i\",\s*rev\s*=\s*\"\w+\"" "$i = { version = \"${latest_version}\"" Cargo.toml
        cargo update -w
    done
}

bump_version() {
    local version="$1"
    local old_version
    local rust_toolchain_version

    old_version=$(get_version)
    rust_toolchain_version=$(get_rust_toolchain_version)

    for i in "${CRATES[@]}"; do
        cargo set-version -p "$i" "${version}"
        cargo update -w
        find . -name "Cargo.toml" -exec sd "^$i\s*=\s*\{\s*version\s*=\s*\"${old_version}\"" "$i = { version = \"${version}\"" {} \;
        cargo update -w
    done

    sd -- 'nightly-\d+-\d+-\d+' "${rust_toolchain_version}" docs/Install.md
    sd -- 'Enarx\s+\d+\.\d+\.\d+-?\w*\.?\d?' "Enarx ${version}" docs/Install.md
    sd -- '--version \d+\.\d+\.\d+-?\w*\.?\d?' "--version ${version}" docs/Install.md
}

#
# Mock registry operations
#

teardown_mock_registry() {
    kill "${REGISTRY_PID}"
    rm -rf "${REGISTRY_PATH}"
    unset REGISTRY_PATH
    unset REGISTRY_PID
    unset MOCKED_REGISTRY
    unset CARGO_REGISTRIES_MOCKED_INDEX
    unset CARGO_REGISTRIES_MOCKED_TOKEN
}

# This makes the necessary changes to the code and documentation to enable testing
enable_mock() {
    local registry="$1"

    for i in "${CRATES[@]}"; do
        find crates/ -name "Cargo.toml" -exec sd "$i\s*=\s*\{" "$i = { registry = \"${registry}\", " {} \;
        sd "$i\s*=\s*\{" "$i = { registry = \"${registry}\", " Cargo.toml
    done
    cargo update -w
    sd -- '--bin enarx --version' "--bin enarx --registry ${registry} --version" docs/Install.md
    # shellcheck disable=SC2016
    sd -- 'clone https://github.com/enarx/enarx' "clone ${REPO_PATH} enarx" docs/Install.md
    MOCK_ON="true"
}

# Removes temporary changes needed for mocked testing
disable_mock() {
    find . -name "Cargo.toml" -exec sd 'registry\s*=\s*"\w+"\s*,\s*' '' {} \;
    sd -- '--registry\s\w+\s' '' docs/Install.md
    sd -- "clone ${REPO_PATH} enarx" 'clone https://github.com/enarx/enarx' docs/Install.md
    MOCK_ON="false"
}

#
# Crate manipulation
#

# Publish against the mock registry previously set up
mock_publish() {
    local registry="$1"

    enable_mock "${registry}"
    for i in sallyport enarx-exec-wasmtime enarx-exec-wasmtime-bin; do
        shout "Publishing mock crate ${i}..."
        cargo publish --allow-dirty --registry "${registry}" -p "$i"
        sleep 2
    done
    for i in enarx-shim-kvm enarx-shim-sgx; do
        shout "Publishing mock crate ${i}..."
        cargo publish --registry "${registry}" -p "$i" --allow-dirty --target x86_64-unknown-none
        sleep 2
    done
    cargo publish --registry "${registry}" -p enarx --allow-dirty
}

# Run the test suite against configured in the 'Constants' section
crate_install_test() {
    # Note: assuming docker is installed, and can be run as current user
    for context in "${CONTEXTS[@]}"; do
        for image in "${IMAGES[@]}"; do
            shout "Running context ${context} on ${image}"
            if [[ "${MOCK_ON}" == "true" ]]; then
                docker run --rm -it \
                    -v "$(realpath docs/Install.md)":/home/user/Install.md \
                    -v "${REGISTRY_PATH}":"${REGISTRY_PATH}":rw \
                    -v "${REPO_DIR}":"${REPO_DIR}":ro \
                    -e CONTEXT="${context}" \
                    -e REGISTRY_PATH="${REGISTRY_PATH}" \
                    -e MOCKED_REGISTRY="${MOCKED_REGISTRY}" \
                    -e CARGO_REGISTRIES_MOCKED_INDEX="$CARGO_REGISTRIES_MOCKED_INDEX" \
                    -e CARGO_REGISTRIES_MOCKED_TOKEN="$CARGO_REGISTRIES_MOCKED_TOKEN" \
                    -e CARGO_NET_GIT_FETCH_WITH_CLI="true" \
                    "${IMAGE_PREFIX}${image}${IMAGE_SUFFIX}"
            else
                docker run --rm -it \
                    -v "$(realpath docs/Install.md)":/home/user/Install.md \
                    -e CONTEXT="${context}" \
                    "${IMAGE_PREFIX}${image}${IMAGE_SUFFIX}"
            fi
        done
    done
}

# Publish the crates
publish() {
    # Fail if code is still in mocked state
    if [[ "${MOCK_ON}" == "true" ]]; then
        echo "ERROR: Cannot publish with code refering to mocked registries"
        exit 1
    fi

    local token
    read -p "Provide token for crates.io: " -r token

    # Dry run for publish (see note at beginning of script)
    if [[ "${DR_PUBLISH}" == "true" ]]; then
        for i in sallyport enarx-exec-wasmtime enarx-exec-wasmtime-bin; do
            echo -e "\n\nDry-run publishing ${i}..."
            cargo publish -p "$i" --dry-run --token "${token}"
            sleep 2
        done
        for i in enarx-shim-kvm enarx-shim-sgx; do
            echo -e "\n\nDry-run publishing ${i}..."
            cargo publish -p "$i" --dry-run --token "${token}" --target x86_64-unknown-none
            sleep 2
        done
        echo -e "\n\nDry-run publishing enarx..."
        cargo publish -p enarx --dry-run --token "${token}"
        should_continue "true"
    fi

    for i in sallyport enarx-exec-wasmtime enarx-exec-wasmtime-bin; do
        echo -e "\n\nPublishing ${i}..."
        cargo publish -p "$i" --token "${token}"
        sleep 2
    done
    for i in enarx-shim-kvm enarx-shim-sgx; do
        echo -e "\n\nPublishing ${i}..."
        cargo publish -p "$i" --target x86_64-unknown-none --token "${token}"
        sleep 2
    done
    echo -e "\n\nPublishing enarx..."
    cargo publish -p enarx --token "${token}"
}

#
# Utility functions
#

# Since we have a lot of output, this makes it easier to refer to key sections/events
shout() {
    echo -e "
#################################################################################################
# $(date)
# $1
#################################################################################################
"
}

# Asks the user if they want to continue with the current action (defaults to 'yes').
# NOTE: some actions cannot be skipped
should_continue() {
    local force_confirm="${1:-false}"
    if [[ "${CONFIRM}" == "true" || "${force_confirm}" == "true" ]]; then
        read -p "Continue? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Runs the following code
on_exit() {
    set +u
    shout "Exiting..."
    if [[ "${CLEANUP}" == "true" ]]; then
        echo "Cleaning up:"
        if [ -n "${CARGO_REGISTRIES_MOCKED_INDEX}" ]; then
            teardown_mock_registry
        fi
        echo "Mock registry torn down"
        rm -rf "${REPO_DIR}"
        echo "Publish registry deleted"
    else
        echo "Repository path: ${REPO_DIR}"
        if [[ "${MOCK_ON}" == "true" ]]; then
            echo "Warning: mock registry references set in code base"
        fi
        if [ -n "${CARGO_REGISTRIES_MOCKED_INDEX}" ]; then
            echo "Mock registry path: ${REGISTRY_PATH}"
            echo "Mock registry name: ${MOCKED_REGISTRY}"
            echo "Mock registry PID: ${REGISTRY_PID}"
            echo "CARGO_REGISTRIES_MOCKED_INDEX=${CARGO_REGISTRIES_MOCKED_INDEX}"
            echo "CARGO_REGISTRIES_MOCKED_TOKEN=${CARGO_REGISTRIES_MOCKED_TOKEN}"
        fi
    fi
    set -u
}
trap on_exit EXIT

if [[ "$DRYRUN" == "true" ]]; then
    shout "Warning: DRYRUN environment variable set, no changes will be made. This process will take a long time."
fi

# Stage 1: Setup
old_version=$(get_version)
echo "Current version: ${old_version}"
read -p "Enter the new crate version: " -r NEW_VERSION
setup_mock_registry
checkout_repository "${NEW_VERSION}"
cd "${REPO_DIR}"

# Stage 1a: Manual adjustments
# This could include merging in any  additional code, e.g. updating the docs/Install.md file with new contexts for features available in release
shout "Pausing to provide ability to do any manual adjustments prior to continuing release process. Repository located here: ${REPO_DIR}"
should_continue "true"

# Stage 2: Crate bump
shout "Ensuring we are not using git revisions in cargo files"
echo "NOTE: Assuming all necessary subcrates were published prior to Enarx release"
update_git_ref_to_crate
echo -e "Done!\n\n"
git --no-pager diff
should_continue

# Stage 3: Version bump
shout "Bumping version from ${old_version} to ${NEW_VERSION}"
bump_version "${NEW_VERSION}"
echo -e "Done!\n\n"
git --no-pager diff
should_continue

# Stage 4: Build & test
shout "Post dependency and version bump tests"
echo "Cleaning cache"
clean
echo "Building..."
build

# Stage 5: Dry run publish/install from mock registry
shout "Running E2E tests"
echo -e "Publishing crates to mock registry...\n\n"
mock_publish "${MOCKED_REGISTRY}"
echo -e "Installing and testing mock crate!\n\n"
crate_install_test
echo -e "Removing mock registry references!\n\n"
disable_mock
echo -e "Tearing down mock registry"
teardown_mock_registry

git --no-pager diff
should_continue

# Stage 6: Sanity check build
shout "Running final sanity check after removing testing changes"
clean
build
echo "About to create commit for release and create PR."
git status

if [[ "$DRYRUN" == "false" ]]; then
    shout "About to create commit for release and create PR. Bellow are the changes to be comitted:"
    git status
    git --no-pager diff
    should_continue "true"

    # Stage 7: Release PR
    shout "Pushing changes to fork"
    echo "NOTE: ensure git is configured with gpg for signing"
    git commit -asS -m "chore(release): Release v${NEW_VERSION}"
    git push origin "release/${NEW_VERSION}"

    echo "About to create PR for release"
    should_continue "true"
    gh pr create -t "chore(release): release v${NEW_VERSION}" \
        -b "chore(release): release v${NEW_VERSION}" \
        --base main \
        -a "@me" \
        -l release \
        -R enarx/enarx

    shout "Please wait until PR is approved and merged."
    echo 'You may also want to run the testdocs workflow to ensure the documentation is tested: https://github.com/enarx/enarx/actions/workflows/test-docs.yml'
    echo "Note, there should be no pushes until the release is finalized"
    should_continue "true"

    # Stage 8: Create release git tag
    shout "Creating release tag"
    git fetch --all --tags
    git checkout upstream/main
    git tag --sign -m "chore(release): release v${NEW_VERSION}" "v${NEW_VERSION}"
    git push upstream "v${NEW_VERSION}"

    # Stage 9: Publish crates
    shout "Please verify if package manifest looks good prior to publishing:"
    cargo package --list
    should_continue "true"
    echo "Publishing"
    publish
    sleep 10

    # Stage 10: Check if can install from released crates
    shout "Check if we can install the new packages"
    crate_install_test
    should_continue "true"

    # Stage 11: GitHub draft release
    shout "Creating draft GitHub release"
    read -p "What's the name of the release (castle name): " -r RELEASE_TITLE
    gh release create -d -p --generate-notes -t "${RELEASE_TITLE}" -R enarx/enarx "v${NEW_VERSION}"
    echo "Please update the release notes on the GitHub release page and publish!"
    echo "After this please follow documentation on triggering Netlify documentation build+publish."
else
    echo "Dry run complete."
fi
