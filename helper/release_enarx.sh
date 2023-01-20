#!/usr/bin/env bash

set -u
set -e

# set -x  # Uncomment to debug

## Constants

# The crates we plan on releasing
readonly CRATES_REG_TARGETS=(enarx-config sallyport enarx-exec-wasmtime shared)
readonly CRATES_UNKNOWN_NONE=(enarx-shim-kvm enarx-shim-sgx)
readonly CRATES=( "${CRATES_REG_TARGETS[@]}" "${CRATES_UNKNOWN_NONE[@]}" enarx )

# Constants for release testing container images
readonly IMAGE_PREFIX="registry.gitlab.com/enarx/misc-testing/"
readonly IMAGES_THOROUGH=(ubuntu debian centos7 centos8 fedora)
readonly IMAGES_FAST=(debian)
readonly IMAGE_SUFFIX="-base:latest"

# E2E/Install documentation contexts used in docs/Install.md to test on container images (test plans)
readonly CONTEXTS=("git,helloworld")

## Flags

readonly CLEANUP="${CLEANUP:-false}"  # Delete cloned repo, mock registry and stop process repository after build
readonly CONFIRM="${CONFIRM:-true}"   # Should we confirm on each step (some steps cannot be skipped)
readonly DRYRUN="${DRYRUN:-true}"     # Do not make any external facing changes. Warning: DRYRUN set to false will disable CLEANUP.
readonly GIT_REPO="${GIT_REPO:-NONE}" # Git repository URL of user's fork of enarx repo
readonly FAST="${FAST:-false}"        # Should we be fast or thorough when conducting pre-release tests

readonly SKIP_TESTS="${SKIP_TESTS:-false}" # Skip tests and jump directly to release. THIS IS NOT RECOMMENDED.
readonly IMAGES_OVERRIDE="${IMAGES_OVERRIDE:-}" #Provide a list of alternative fast images

## Globals

export MOCK_ON="false"
export REPO_DIR=""
export REPO_PATH=""
export REGISTRY_PATH=""
export REGISTRY_PID=""
export MOCKED_REGISTRY=""
export CARGO_REGISTRIES_MOCKED_INDEX=""
export CARGO_REGISTRIES_MOCKED_TOKEN=""
export IMAGES=""

## Initial setup

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
    if [[ "$GIT_REPO" == "NONE" ]]; then
        read -p "Provide git repository URL for user's fork: " -r FORK_URL
    else
        FORK_URL="$GIT_REPO"
    fi
    git clone "$FORK_URL" .
    git remote add upstream git@github.com:enarx/enarx.git >/dev/null 2>&1
    git fetch --all --tags >/dev/null 2>&1
    git checkout -b "release/${version}" upstream/main >/dev/null 2>&1

    realpath "${REPO_DIR}"
}

## Code building

build() {
    cargo run -- platform info
    echo -e "\n\n\n"
    cargo test
    echo -e "\n\n\n"
}

clean() {
    cargo clean -r
    cargo fetch
}

## Version functions

get_version() {
    rg '^version = ' Cargo.toml | cut -d\" -f2
}

get_rust_toolchain_version() {
    grep channel rust-toolchain.toml | cut -d \" -f 2
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
    sd -- '\d+\.\d+\.\d+' "${version}" docs/Quickstart.mdx
}


# Run the test suite against configured in the 'Constants' section
install_test() {
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


## Utility functions

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
        if [[ "${DRYRUN}" == "true" ]]; then
            rm -rf "${REPO_DIR}"
            echo "Publish repository deleted"
        else
            echo "Publish repository not deleted due to DRYRUN set to 'false'"
        fi
    else
        echo "Repository path: ${REPO_DIR}"
    fi
    set -u
}
trap on_exit EXIT


if [[ "$FAST" == "true" ]]; then
    echo -e "Warning: FAST=true environment variable set, will only test with single image."
# Use this varible to have an alternative FAST image
    if [[ ! -z "${IMAGES_OVERRIDE}" ]]; then
        IMAGES=( "${IMAGES_OVERRIDE[@]}" )
    else
        IMAGES=( "${IMAGES_FAST[@]}" )
    fi
else
    shout "FAST=true environment variable not set, will test with all images. This will take up to 90 minutes for the entire process"
    IMAGES=( "${IMAGES_THOROUGH[@]}" )
fi

if [[ "$DRYRUN" == "true" ]]; then
    shout "Warning: DRYRUN environment variable set, no changes will be made. This process will take a long time."
fi


# Stage 1: Setup
old_version=$(get_version)
echo "Current version: ${old_version}"
read -p "Enter the new Enarx version: " -r NEW_VERSION
checkout_repository "${NEW_VERSION}"
cd "${REPO_DIR}"

# Stage 2: Manual adjustments
# This could include merging in any  additional code, e.g. updating the docs/Install.md file with new contexts for features available in release
shout "Pausing to provide ability to do any manual adjustments prior to continuing release process. Repository located here: ${REPO_DIR}"
should_continue "true"

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
should_continue

if [[ "$SKIP_TESTS" == "true" ]]; then
    shout "Warning: SKIP_TESTS environment variable set, no tests will be run. This is VERY dangerous."
    should_continue "true"
else
    # Stage 5: Dry run publish/install from mock registry
    shout "Running E2E tests"
    install_test

    # Stage 6: Sanity check build
    clean
    build
    echo "About to create commit for release and create PR."
    git status
fi

if [[ "$DRYRUN" == "false" ]]; then
    shout "About to create commit for release and create PR. Bellow are the changes to be comitted:"
    git status
    git --no-pager diff
    should_continue "true"

    # Stage 7: Release PR
    shout "Pushing changes to fork"
    echo "NOTE: ensure git is configured with gpg for signing"
    git commit -asS -m "chore(release): release v${NEW_VERSION}"
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

    shout "Done!"
else
    echo "Dry run complete."
fi
