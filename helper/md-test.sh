#!/usr/bin/env bash

set -eu

# Constants
readonly HOMEDIR="/home/user"
readonly IMAGE_PREFIX="registry.gitlab.com/enarx/misc-testing/"
readonly IMAGE_SUFFIX="-base:latest"

#
# Valid parameters examples
#
# readonly IMAGES=( ubuntu
#                   debian
#                   centos7
#                   centos8
#                   fedora )
# readonly CONTEXTS_BASIC=( git,helloworld crates,helloworld ) # For direct backend
# readonly CONTEXTS_KVM=( git,helloworld,kvm-helloworld,kvm crates,helloworld,kvm-helloworld,kvm ) # For KVM

test_image_kvm() {
    local markdown_doc_path="$(realpath "$1")"
    local image="$2"
    local context="$3"
    echo -e "\n\nRunning: ${image} (KVM)"
    echo "Context: \"${context}\""
    echo "Markdown Document: \"${markdown_doc_path}\""
    time docker run \
        --rm \
        --device /dev/kvm --privileged \
        -v "${markdown_doc_path}":"${HOMEDIR}/Install.md":ro \
        -e CONTEXT="${context}" "${image}"
    status=$?
    if [[ $status -eq 0 ]]; then
        echo -e "Run with ${image} (KVM) and context \"${context}\" suceeded!\n\n"
    else
        echo "Run with ${image} (KVM) and context \"${context}\" failed!" | tee /dev/stderr
        exit $status
    fi
}

test_image_basic() {
    local markdown_doc_path="$(realpath "$1")"
    local image="$2"
    local context="$3"
    echo -e "\n\nRunning: ${image}"
    echo "Context: \"${context}\""
    echo "Markdown Document: \"${markdown_doc_path}\""
    time docker run \
        --rm \
        -v "${markdown_doc_path}":"${HOMEDIR}/Install.md":ro \
        -e CONTEXT="${context}" "${image}"
    status=$?
    if [[ $status -eq 0 ]]; then
        echo -e "Run with ${image} and context \"${context}\" suceeded!\n\n"
    else
        echo "Run with ${image} and context \"${context}\" failed!" | tee /dev/stderr
        exit $status
    fi
}

alias_function () {
    local ORIG_FUNC=$(declare -f $1)
    local NEWNAME_FUNC="$2${ORIG_FUNC#$1}"
    eval "$NEWNAME_FUNC"
}


usage() {
    local PROGNAME=${0##*/}

    cat << EOF
Usage: $PROGNAME [OPTION]
  -h, --help             Display this help
  […]                    TODO
EOF
}

TEMP=$(
    getopt -o '' \
        --long images: \
        --long context: \
        --long document: \
        --long mode: \
        --long help \
        -- "$@"
    )

if (( $? != 0 )); then
    usage >&2
    exit 1
fi

eval set -- "$TEMP"
unset TEMP

declare -a IMAGES CONTEXT
declare MODE DOCUMENT

while true; do
    case "$1" in
        '--images')
            IFS=, read -r -a IMAGES <<<"$2"
            shift 2; continue
            ;;
        '--context')
            read -r -a CONTEXT <<<"$2"
            shift 2; continue
            ;;
        '--mode')
            MODE="$2"
            if [[ $MODE != "kvm" ]] && [[ $MODE != "basic" ]] ; then
              usage
              exit 1
            fi
            shift 2; continue
            ;;
        '--document')
            DOCUMENT="$2"
            shift 2; continue
            ;;
        '--help')
            usage
            exit 0
            ;;
        '--')
            shift
            break
            ;;
        *)
            echo 'Internal error!' >&2
            exit 1
            ;;
    esac
done

if [[ "$MODE" == "kvm" ]]; then
    alias_function test_image_kvm test_image
else
    alias_function test_image_basic test_image
fi

echo "Markdown Document: ${DOCUMENT}" 
echo "Contexts:"
for context in "${CONTEXT[@]}"; do echo "    - ${context}"; done 
echo -e "\nImages:"
for image in "${IMAGES[@]}"; do echo "    - ${IMAGE_PREFIX}${image}${IMAGE_SUFFIX}"; done 
echo -e "\n\n"
sleep 2

for context in "${CONTEXT[@]}"; do
    for image in "${IMAGES[@]}"; do
        image_name="${IMAGE_PREFIX}${image}${IMAGE_SUFFIX}"
        test_image "${DOCUMENT}" "${image_name}"  "${context}"
    done
done


echo "Testing completed!"
