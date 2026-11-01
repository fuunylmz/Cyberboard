#!/usr/bin/env bash
set -euo pipefail

if [[ "${GOSUMDB:-}" == "off" ]]; then
	echo "GOSUMDB=off is not allowed for this build" >&2
	exit 1
fi
if [[ -n "${GONOSUMDB:-}" || -n "${GOPRIVATE:-}" || -n "${GOINSECURE:-}" ]]; then
	echo "GONOSUMDB, GOPRIVATE, and GOINSECURE must be unset or empty for this build" >&2
	exit 1
fi
export GOFLAGS="-mod=readonly"

readonly VERSION="1.14.4"
readonly TAG="v${VERSION}"
readonly EXPECTED_COMMIT="c005f35300ce76427dc285481ec5695f5b179cd2"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
readonly DEFAULT_OUTPUT_DIR="${REPO_ROOT}/target/sing-box"
readonly OUTPUT_DIR="${SING_BOX_OUTPUT_DIR:-${DEFAULT_OUTPUT_DIR}}"
readonly BUILD_ROOT="${SING_BOX_BUILD_TMP:-${TMPDIR:-/tmp}/sing-box-build}"
readonly SOURCE_DIR="${SING_BOX_SOURCE_DIR:-${BUILD_ROOT}/source}"
readonly REPOSITORY="https://github.com/SagerNet/sing-box.git"
readonly TARGETS="${SING_BOX_TARGETS:-darwin/arm64 linux/amd64 linux/arm64}"
read -r -a target_list <<< "${TARGETS}"
if (( ${#target_list[@]} == 0 )); then
	echo "SING_BOX_TARGETS must contain at least one GOOS/GOARCH target" >&2
	exit 1
fi

mkdir -p "${BUILD_ROOT}" "${OUTPUT_DIR}"
export GOPATH="${BUILD_ROOT}/gopath"
export GOMODCACHE="${BUILD_ROOT}/gomodcache"
export GOCACHE="${BUILD_ROOT}/gocache"
mkdir -p "${GOPATH}" "${GOMODCACHE}" "${GOCACHE}"

if [[ ! -d "${SOURCE_DIR}/.git" ]]; then
	if [[ -e "${SOURCE_DIR}" ]]; then
		echo "Source directory exists but is not a git checkout: ${SOURCE_DIR}" >&2
		exit 1
	fi
	git clone --depth 1 --branch "${TAG}" "${REPOSITORY}" "${SOURCE_DIR}"
fi

actual_commit="$(git -C "${SOURCE_DIR}" rev-parse HEAD)"
if [[ "${actual_commit}" != "${EXPECTED_COMMIT}" ]]; then
	echo "${TAG} commit mismatch: expected ${EXPECTED_COMMIT}, got ${actual_commit}" >&2
	exit 1
fi

if [[ -n "$(git -C "${SOURCE_DIR}" status --porcelain)" ]]; then
	echo "Source checkout must be clean and unmodified: ${SOURCE_DIR}" >&2
	exit 1
fi

if [[ "$(git -C "${SOURCE_DIR}" describe --tags --exact-match HEAD)" != "${TAG}" ]]; then
	echo "Source checkout is not exactly tagged ${TAG}" >&2
	exit 1
fi

default_tags_file="${SOURCE_DIR}/release/DEFAULT_BUILD_TAGS"
ldflags_file="${SOURCE_DIR}/release/LDFLAGS"
[[ -s "${default_tags_file}" && -s "${ldflags_file}" ]] || {
	echo "Missing upstream build metadata in ${SOURCE_DIR}/release" >&2
	exit 1
}

tags="$(tr ',' '\n' < "${default_tags_file}" | awk 'NF && $0 != "with_naive_outbound"' | paste -sd ',' -)"
if [[ ",${tags}," != *",with_v2ray_api,"* ]]; then
	tags="${tags},with_v2ray_api"
fi
upstream_ldflags="$(<"${ldflags_file}")"
ldflags="${upstream_ldflags} -X github.com/sagernet/sing-box/constant.Version=${VERSION}"

for target in "${target_list[@]}"; do
	if [[ "${target}" != */* ]]; then
		echo "Invalid target '${target}', expected GOOS/GOARCH" >&2
		exit 1
	fi
	goos="${target%/*}"
	goarch="${target#*/}"
	case "${target}" in
		darwin/arm64) output="${OUTPUT_DIR}/sing-box" ;;
		*) output="${OUTPUT_DIR}/sing-box-${goos}-${goarch}" ;;
	esac
	echo "Building ${TAG} for ${target} (tags: ${tags})"
	(
		cd "${SOURCE_DIR}"
		CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" \
			go build -trimpath -tags "${tags}" -ldflags "${ldflags}" \
			-o "${output}" ./cmd/sing-box
	)
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "${output}"
	else
		shasum -a 256 "${output}"
	fi
done
