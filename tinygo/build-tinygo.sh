#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
V2_ROOT="$REPO_ROOT/v2"
TOOLCHAIN_DIR="$SCRIPT_DIR/toolchain"
MANIFEST_FILE="$TOOLCHAIN_DIR/manifest.env"
PATCH_FILE="$TOOLCHAIN_DIR/regexp-syntax-repeat.patch"
CACHE_ROOT="$SCRIPT_DIR/.toolchain"

if [ ! -f "$MANIFEST_FILE" ]; then
    echo "missing toolchain manifest: $MANIFEST_FILE" >&2
    exit 1
fi

# shellcheck disable=SC1090
source "$MANIFEST_FILE"

OUTPUT_PATH=""
PREPARE_ONLY=0
FORCE_PREPARE=0
CLEAN_CACHE=0
EXTRA_TINYGO_ARGS=()
TMP_PREPARE_DIR=""
GO_CMD="${GO_CMD:-}"
TINYGO_CMD="${TINYGO_CMD:-}"
GIT_CMD="${GIT_CMD:-}"
WINDOWS_HOME_RAW=""
WINDOWS_HOME_UNIX=""
BUILD_PROFILE="release"
UPX_MODE="auto"
APPEND_TAGS=""
DEFAULT_RELEASE_TAGS="forceposix noembed osusergo netgo goregexp"
STRIP_CMD=""
UPX_CMD=""

log() {
    printf '[tinygo-build] %s\n' "$*"
}

fail() {
    printf '[tinygo-build] %s\n' "$*" >&2
    exit 1
}

cleanup() {
    if [ -n "$TMP_PREPARE_DIR" ] && [ -d "$TMP_PREPARE_DIR" ]; then
        rm -rf "$TMP_PREPARE_DIR"
    fi
}

trap cleanup EXIT

usage() {
    cat <<'EOF'
Usage: bash tinygo/build-tinygo.sh [options] [-- <extra tinygo args>]

Options:
  -o, --output PATH     Output binary path. Relative paths are resolved from v2/.
      --tags TAGS       Extra build tags to append to the default release tags.
      --profile NAME    Build profile: release, minimal, or compat. Default: release.
      --upx             Require UPX compression with `--best --lzma`.
      --no-upx          Disable UPX compression.
      --prepare-only    Prepare the patched GOROOT cache and exit.
      --force-prepare   Rebuild the cached patched GOROOT.
      --clean-cache     Remove cached patched GOROOT directories and exit.
  -h, --help            Show this help.

Examples:
  bash tinygo/build-tinygo.sh
  bash tinygo/build-tinygo.sh -o dist/gogo_tinygo_release.exe
  GOOS=linux GOARCH=amd64 bash tinygo/build-tinygo.sh -- -opt=z

Environment:
  ALLOW_TOOLCHAIN_MISMATCH=1  bypass pinned Go/TinyGo version checks.
  BASE_GOROOT=...             override the host GOROOT used as the patch base.
  GO_CMD=...                  override the `go` executable path.
  TINYGO_CMD=...              override the `tinygo` executable path.
  GIT_CMD=...                 override the `git` executable path.
EOF
}

is_windows_path() {
    case "$1" in
        [A-Za-z]:\\*|[A-Za-z]:/*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

to_unix_path() {
    local raw="$1"
    if is_windows_path "$raw"; then
        if command -v cygpath >/dev/null 2>&1; then
            cygpath -u "$raw"
            return
        fi
        if command -v wslpath >/dev/null 2>&1; then
            wslpath -u "$raw"
            return
        fi
    fi
    printf '%s\n' "$raw"
}

to_native_path() {
    local raw="$1"
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -w "$raw"
        return
    fi
    if command -v wslpath >/dev/null 2>&1; then
        wslpath -w "$raw"
        return
    fi
    printf '%s\n' "$raw"
}

cmd_uses_windows_paths() {
    local cmd="$1"
    if is_windows_path "$cmd"; then
        return 0
    fi
    case "$(basename "$cmd")" in
        *.exe|*.EXE)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

path_for_cmd() {
    local cmd="$1"
    local unix_path="$2"
    local native_path="$3"
    if cmd_uses_windows_paths "$cmd"; then
        printf '%s\n' "$native_path"
    else
        printf '%s\n' "$unix_path"
    fi
}

detect_windows_home() {
    if [ -n "$WINDOWS_HOME_UNIX" ]; then
        printf '%s\n' "$WINDOWS_HOME_UNIX"
        return
    fi
    if command -v powershell.exe >/dev/null 2>&1; then
        WINDOWS_HOME_RAW="$(powershell.exe -NoProfile -Command "[Environment]::GetFolderPath(\"UserProfile\")" 2>/dev/null | tr -d '\r' | tail -n 1 || true)"
        if [ -n "$WINDOWS_HOME_RAW" ]; then
            WINDOWS_HOME_UNIX="$(to_unix_path "$WINDOWS_HOME_RAW")"
            printf '%s\n' "$WINDOWS_HOME_UNIX"
            return
        fi
    fi
    return 1
}

hash_file() {
    local path="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$path" | awk '{print $1}'
        return
    fi
    "$GIT_CMD" hash-object "$path"
}

copy_tree() {
    local src="$1"
    local dst="$2"
    mkdir -p "$dst"
    if command -v tar >/dev/null 2>&1; then
        (
            cd "$src"
            tar -chf - .
        ) | (
            cd "$dst"
            tar -xf -
        )
        return
    fi

    cp -aL "$src"/. "$dst"/
}

regexp_patch_present() {
    local root="$1"
    local compile_file="$root/src/regexp/syntax/compile.go"
    local simplify_file="$root/src/regexp/syntax/simplify.go"
    grep -q 'case OpRepeat:' "$compile_file" &&
        grep -q 'func (c \*compiler) repeat(' "$compile_file" &&
        grep -q 'Preserve counted repeats so Compile can lower them directly.' "$simplify_file"
}

apply_regexp_patch() {
    local root="$1"
    if regexp_patch_present "$root"; then
        log "regexp patch already present in prepared GOROOT"
        return
    fi

    log "applying regexp patch"
    (
        cd "$root"
        GIT_CEILING_DIRECTORIES="$CACHE_ROOT" "$GIT_CMD" apply --recount "$PATCH_FILE"
    ) || fail "failed to apply $PATCH_FILE to $root"

    regexp_patch_present "$root" || fail "regexp patch verification failed after apply"
}

resolve_output_path() {
    local target_goos="$1"
    local target_goarch="$2"
    local suffix=""
    if [ "$target_goos" = "windows" ]; then
        suffix=".exe"
    fi

    if [ -n "$OUTPUT_PATH" ]; then
        case "$OUTPUT_PATH" in
            /*|[A-Za-z]:/*|[A-Za-z]:\\*)
                printf '%s\n' "$OUTPUT_PATH"
                ;;
            *)
                printf '%s/%s\n' "$V2_ROOT" "$OUTPUT_PATH"
                ;;
        esac
        return
    fi

    local host_goos
    local host_goarch
    host_goos="$("$GO_CMD" env GOHOSTOS)"
    host_goarch="$("$GO_CMD" env GOHOSTARCH)"

    if [ "$target_goos" = "$host_goos" ] && [ "$target_goarch" = "$host_goarch" ]; then
        printf '%s/dist/gogo_tinygo%s\n' "$V2_ROOT" "$suffix"
    else
        printf '%s/dist/gogo_tinygo_%s_%s%s\n' "$V2_ROOT" "$target_goos" "$target_goarch" "$suffix"
    fi
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -o|--output)
            [ "$#" -ge 2 ] || fail "missing value for $1"
            OUTPUT_PATH="$2"
            shift 2
            ;;
        --tags)
            [ "$#" -ge 2 ] || fail "missing value for $1"
            APPEND_TAGS="$2"
            shift 2
            ;;
        --profile)
            [ "$#" -ge 2 ] || fail "missing value for $1"
            BUILD_PROFILE="$2"
            shift 2
            ;;
        --upx)
            UPX_MODE="force"
            shift
            ;;
        --no-upx)
            UPX_MODE="off"
            shift
            ;;
        --prepare-only)
            PREPARE_ONLY=1
            shift
            ;;
        --force-prepare)
            FORCE_PREPARE=1
            shift
            ;;
        --clean-cache)
            CLEAN_CACHE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            EXTRA_TINYGO_ARGS+=("$@")
            break
            ;;
        *)
            EXTRA_TINYGO_ARGS+=("$1")
            shift
            ;;
    esac
done

resolve_cmd() {
    local name="$1"
    local home_unix=""
    local candidate=""
    if command -v "$name" >/dev/null 2>&1; then
        command -v "$name"
        return 0
    fi
    if command -v "${name}.exe" >/dev/null 2>&1; then
        command -v "${name}.exe"
        return 0
    fi
    home_unix="$(detect_windows_home || true)"
    if [ -n "$home_unix" ]; then
        case "$name" in
            go)
                for candidate in \
                    "$home_unix/.g/go/bin/go.exe" \
                    "/c/Go/bin/go.exe"
                do
                    if [ -x "$candidate" ]; then
                        printf '%s\n' "$candidate"
                        return 0
                    fi
                done
                ;;
            tinygo)
                for candidate in \
                    "$home_unix/scoop/apps/tinygo/current/bin/tinygo.exe" \
                    "$home_unix/scoop/shims/tinygo.exe"
                do
                    if [ -x "$candidate" ]; then
                        printf '%s\n' "$candidate"
                        return 0
                    fi
                done
                ;;
            git)
                for candidate in \
                    "$home_unix/scoop/shims/git.exe" \
                    "$home_unix/scoop/apps/git/current/bin/git.exe"
                do
                    if [ -x "$candidate" ]; then
                        printf '%s\n' "$candidate"
                        return 0
                    fi
                done
                ;;
            llvm-strip|strip|objcopy)
                for candidate in \
                    "/d/SDK/msys2/mingw64/bin/${name}.exe" \
                    "/c/msys64/mingw64/bin/${name}.exe"
                do
                    if [ -x "$candidate" ]; then
                        printf '%s\n' "$candidate"
                        return 0
                    fi
                done
                ;;
            upx)
                for candidate in \
                    "$home_unix/scoop/shims/upx.exe" \
                    "$home_unix/scoop/apps/upx/current/upx.exe" \
                    "/d/SDK/msys2/mingw64/bin/upx.exe" \
                    "/c/msys64/mingw64/bin/upx.exe"
                do
                    if [ -x "$candidate" ]; then
                        printf '%s\n' "$candidate"
                        return 0
                    fi
                done
                ;;
        esac
    fi
    return 1
}

resolve_strip_cmd() {
    local candidate=""
    local resolved=""
    for candidate in llvm-strip strip objcopy; do
        if resolved="$(resolve_cmd "$candidate" 2>/dev/null)"; then
            printf '%s\n' "$resolved"
            return 0
        fi
    done
    return 1
}

resolve_upx_cmd() {
    local resolved=""
    if resolved="$(resolve_cmd upx 2>/dev/null)"; then
        printf '%s\n' "$resolved"
        return 0
    fi
    return 1
}

native_slash_path() {
    to_native_path "$1" | sed 's#\\#/#g'
}

resolve_mingw_root() {
    local candidate=""
    if [ -n "${MINGW_ROOT:-}" ]; then
        candidate="$(to_unix_path "$MINGW_ROOT")"
        if [ -d "$candidate" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    fi

    if [ -n "$STRIP_CMD" ]; then
        candidate="$(dirname "$(dirname "$STRIP_CMD")")"
        if [ -d "$candidate/lib" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    fi

    for candidate in /d/SDK/msys2/mingw64 /c/msys64/mingw64; do
        if [ -d "$candidate/lib" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

    return 1
}

resolve_mingw_libgcc_dir() {
    local root="$1"
    local libgcc=""
    for libgcc in "$root"/lib/gcc/x86_64-w64-mingw32/*/libgcc.a; do
        if [ -f "$libgcc" ]; then
            dirname "$libgcc"
            return 0
        fi
    done
    return 1
}

add_windows_link_flags() {
    if [ "$TARGET_GOOS" != "windows" ] || [ "$TARGET_GOARCH" != "amd64" ]; then
        return
    fi

    local mingw_root=""
    local libgcc_dir=""
    if ! mingw_root="$(resolve_mingw_root 2>/dev/null)" || ! libgcc_dir="$(resolve_mingw_libgcc_dir "$mingw_root" 2>/dev/null)"; then
        log "mingw libgcc not found; windows link may fail on ___chkstk_ms"
        return
    fi

    local libgcc_dir_native=""
    local mingw_lib_native=""
    libgcc_dir_native="$(native_slash_path "$libgcc_dir")"
    mingw_lib_native="$(native_slash_path "$mingw_root/lib")"
    TINYGO_FLAGS+=(-ldflags "-extldflags \"-L$libgcc_dir_native -L$mingw_lib_native -lgcc\"")
    log "windows link flags: using libgcc from $libgcc_dir"
}

if [ -n "$TINYGO_CMD" ]; then
    TINYGO_CMD="$(to_unix_path "$TINYGO_CMD")"
else
    TINYGO_CMD="$(resolve_cmd tinygo)" || fail "tinygo is not in PATH"
fi

if [ -n "$GO_CMD" ]; then
    GO_CMD="$(to_unix_path "$GO_CMD")"
else
    GO_CMD="$(resolve_cmd go)" || fail "go is not in PATH"
fi

if [ -n "$GIT_CMD" ]; then
    GIT_CMD="$(to_unix_path "$GIT_CMD")"
else
    GIT_CMD="$(resolve_cmd git)" || fail "git is not in PATH"
fi

STRIP_CMD="$(resolve_strip_cmd || true)"
UPX_CMD="$(resolve_upx_cmd || true)"

export PATH="$(dirname "$GO_CMD"):$(dirname "$TINYGO_CMD"):$(dirname "$GIT_CMD"):$PATH"

GO_VERSION="$("$GO_CMD" version | awk '{print $3}')"
TINYGO_VERSION="$("$TINYGO_CMD" version | awk '{print $3}')"
BASE_GOROOT_RAW="${BASE_GOROOT:-$("$TINYGO_CMD" env GOROOT | tr -d '\r')}"
if [ -z "$BASE_GOROOT_RAW" ]; then
    BASE_GOROOT_RAW="$(dirname "$(dirname "$GO_CMD")")"
fi
BASE_GOROOT_UNIX="$(to_unix_path "$BASE_GOROOT_RAW")"
PATCH_HASH="$(hash_file "$PATCH_FILE")"
PATCH_HASH_SHORT="${PATCH_HASH%${PATCH_HASH#????????????}}"
CACHE_KEY="${PATCH_NAME}-${GO_VERSION}-${PATCH_HASH_SHORT}"
PATCHED_GOROOT_UNIX="$CACHE_ROOT/$CACHE_KEY"
PATCHED_GOROOT_NATIVE="$(to_native_path "$PATCHED_GOROOT_UNIX")"
PATCHED_GOROOT_FOR_TINYGO="$(path_for_cmd "$TINYGO_CMD" "$PATCHED_GOROOT_UNIX" "$PATCHED_GOROOT_NATIVE")"
PREPARED_MARKER="$PATCHED_GOROOT_UNIX/.prepared"

if [ "${ALLOW_TOOLCHAIN_MISMATCH:-0}" != "1" ]; then
    [ "$GO_VERSION" = "$EXPECTED_GO_VERSION" ] || fail "expected Go $EXPECTED_GO_VERSION, got $GO_VERSION. Set ALLOW_TOOLCHAIN_MISMATCH=1 to override."
    [ "$TINYGO_VERSION" = "$EXPECTED_TINYGO_VERSION" ] || fail "expected TinyGo $EXPECTED_TINYGO_VERSION, got $TINYGO_VERSION. Set ALLOW_TOOLCHAIN_MISMATCH=1 to override."
fi

[ -d "$BASE_GOROOT_UNIX" ] || fail "base GOROOT does not exist: $BASE_GOROOT_RAW"

mkdir -p "$CACHE_ROOT"

if [ "$CLEAN_CACHE" -eq 1 ]; then
    log "removing cached patched GOROOT directories under $CACHE_ROOT"
    rm -rf "$CACHE_ROOT"/"${PATCH_NAME}"-*
    exit 0
fi

prepare_toolchain() {
    if [ "$FORCE_PREPARE" -eq 1 ]; then
        log "force rebuilding patched GOROOT cache"
        rm -rf "$PATCHED_GOROOT_UNIX"
    fi

    if [ -f "$PREPARED_MARKER" ]; then
        log "using cached patched GOROOT: $PATCHED_GOROOT_UNIX"
        return
    fi

    TMP_PREPARE_DIR="$(mktemp -d "$CACHE_ROOT/.prepare.${CACHE_KEY}.XXXXXX")"
    log "copying base GOROOT from $BASE_GOROOT_RAW"
    copy_tree "$BASE_GOROOT_UNIX" "$TMP_PREPARE_DIR"
    apply_regexp_patch "$TMP_PREPARE_DIR"

    cat > "$TMP_PREPARE_DIR/.prepared" <<EOF
cache_key=$CACHE_KEY
patch_name=$PATCH_NAME
patch_hash=$PATCH_HASH
base_goroot=$BASE_GOROOT_RAW
go_version=$GO_VERSION
tinygo_version=$TINYGO_VERSION
EOF

    rm -rf "$PATCHED_GOROOT_UNIX"
    mv "$TMP_PREPARE_DIR" "$PATCHED_GOROOT_UNIX"
    TMP_PREPARE_DIR=""
    log "prepared patched GOROOT: $PATCHED_GOROOT_UNIX"
}

prepare_toolchain

if [ "$PREPARE_ONLY" -eq 1 ]; then
    log "prepare-only complete"
    log "GOROOT=$PATCHED_GOROOT_FOR_TINYGO"
    exit 0
fi

TARGET_GOOS="${GOOS:-$("$GO_CMD" env GOHOSTOS)}"
TARGET_GOARCH="${GOARCH:-$("$GO_CMD" env GOHOSTARCH)}"
OUTPUT_UNIX="$(resolve_output_path "$TARGET_GOOS" "$TARGET_GOARCH")"
mkdir -p "$(dirname "$OUTPUT_UNIX")"
OUTPUT_NATIVE="$(to_native_path "$OUTPUT_UNIX")"
OUTPUT_FOR_TINYGO="$(path_for_cmd "$TINYGO_CMD" "$OUTPUT_UNIX" "$OUTPUT_NATIVE")"
BUILD_TAGS="tinygo $DEFAULT_RELEASE_TAGS"

if [ -n "$APPEND_TAGS" ]; then
    NORMALIZED_TAGS="$(printf '%s' "$APPEND_TAGS" | tr ',' ' ')"
    BUILD_TAGS="$BUILD_TAGS $NORMALIZED_TAGS"
fi

case "$BUILD_PROFILE" in
    release)
        TINYGO_FLAGS=(-no-debug -opt=z)
        SHOULD_STRIP=1
        PROFILE_AUTO_UPX=1
        ;;
    minimal)
        TINYGO_FLAGS=(-no-debug -opt=z)
        SHOULD_STRIP=1
        PROFILE_AUTO_UPX=1
        if [ "$TARGET_GOOS" != "windows" ]; then
            TINYGO_FLAGS+=(-gc=leaking)
        fi
        ;;
    compat)
        TINYGO_FLAGS=(-no-debug -opt=z)
        SHOULD_STRIP=0
        PROFILE_AUTO_UPX=0
        ;;
    *)
        fail "unknown build profile: $BUILD_PROFILE (expected release, minimal, or compat)"
        ;;
esac

add_windows_link_flags

log "building v2/cmd/tinygo"
log "using patched GOROOT: $PATCHED_GOROOT_FOR_TINYGO"
log "output: $OUTPUT_UNIX"
log "profile: $BUILD_PROFILE"
log "tags: $BUILD_TAGS"
log "upx mode: $UPX_MODE"

export GOROOT="$PATCHED_GOROOT_FOR_TINYGO"

(
    cd "$V2_ROOT"
    "$TINYGO_CMD" build \
        -tags "$BUILD_TAGS" \
        "${TINYGO_FLAGS[@]}" \
        "${EXTRA_TINYGO_ARGS[@]}" \
        -o "$OUTPUT_FOR_TINYGO" \
        ./cmd/tinygo
)

if [ "$SHOULD_STRIP" -eq 1 ]; then
    if [ -n "$STRIP_CMD" ]; then
        OUTPUT_FOR_STRIP="$(path_for_cmd "$STRIP_CMD" "$OUTPUT_UNIX" "$OUTPUT_NATIVE")"
        case "$(basename "$STRIP_CMD")" in
            objcopy|objcopy.exe)
                "$STRIP_CMD" --strip-all "$OUTPUT_FOR_STRIP"
                ;;
            *)
                "$STRIP_CMD" "$OUTPUT_FOR_STRIP"
                ;;
        esac
        log "stripped symbols with $(basename "$STRIP_CMD")"
    else
        log "strip tool not found; leaving symbols intact"
    fi
fi

SHOULD_UPX=0
case "$UPX_MODE" in
    force)
        SHOULD_UPX=1
        ;;
    off)
        SHOULD_UPX=0
        ;;
    auto)
        SHOULD_UPX="$PROFILE_AUTO_UPX"
        ;;
    *)
        fail "unknown upx mode: $UPX_MODE"
        ;;
esac

if [ "$SHOULD_UPX" -eq 1 ]; then
    if [ -n "$UPX_CMD" ]; then
        OUTPUT_FOR_UPX="$(path_for_cmd "$UPX_CMD" "$OUTPUT_UNIX" "$OUTPUT_NATIVE")"
        "$UPX_CMD" --best --lzma "$OUTPUT_FOR_UPX"
        log "compressed with $(basename "$UPX_CMD") --best --lzma"
    elif [ "$UPX_MODE" = "force" ]; then
        fail "upx requested but not found"
    else
        log "upx not found; leaving binary uncompressed"
    fi
fi

log "build finished: $OUTPUT_UNIX"
