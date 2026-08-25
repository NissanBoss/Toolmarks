#!/bin/sh
# Build the package for this machine.
#
#   sh build.sh                            a local build, version "unreleased"
#   sh build.sh v1                         stamped with a version
#   sh build.sh v1 x86_64-apple-darwin     built for another architecture
#
# Rust needs a linker for whatever it is building for, so unlike a Go
# program this cannot be cross compiled to anywhere from anywhere. The one
# exception is macOS, where the compiler that comes with the machine can
# target both architectures, and that is what the third argument is for: it
# means one Mac can produce both Mac packages, so the release does not have
# to wait on an Intel runner that GitHub is in the middle of retiring.

set -e
cd "$(dirname "$0")"

VERSION="${1:-$GITHUB_REF_NAME}"
TARGET="$2"

if [ -n "$VERSION" ]; then
    export TOOLMARKS_VERSION="$VERSION"
    echo "Version: $VERSION"
else
    echo "Version: unreleased (no tag given)"
fi

# What to call the package, and what the binary inside it is called.
if [ -n "$TARGET" ]; then
    case "$TARGET" in
        x86_64-apple-darwin)   NAME="toolmarks-mac-intel";  BINARY="toolmarks" ;;
        aarch64-apple-darwin)  NAME="toolmarks-mac-apple";  BINARY="toolmarks" ;;
        *-windows-*)           NAME="toolmarks-$TARGET";    BINARY="toolmarks.exe" ;;
        *)                     NAME="toolmarks-$TARGET";    BINARY="toolmarks" ;;
    esac
else
    case "$(uname -s)" in
        Linux*)               NAME="toolmarks-linux";   BINARY="toolmarks" ;;
        Darwin*)              NAME="toolmarks-mac";     BINARY="toolmarks" ;;
        MINGW*|MSYS*|CYGWIN*) NAME="toolmarks-windows"; BINARY="toolmarks.exe" ;;
        *) NAME="toolmarks-$(uname -s | tr '[:upper:]' '[:lower:]')"; BINARY="toolmarks" ;;
    esac
    case "$(uname -m)" in
        arm64|aarch64) [ "$NAME" = "toolmarks-mac" ] && NAME="toolmarks-mac-apple" || NAME="$NAME-arm" ;;
        *)             [ "$NAME" = "toolmarks-mac" ] && NAME="toolmarks-mac-intel" || true ;;
    esac
fi
echo "Package: $NAME"
echo ""

# The checks run on the build for this machine. A second build of the same
# tree for another architecture is the same source and does not need them
# again, and running the tests under emulation would only prove that the
# emulator works.
if [ -z "$TARGET" ]; then
    echo "Checking before building..."
    cargo fmt --check
    cargo clippy --all-targets -- -D warnings
    cargo test --quiet
    echo "  all good"
    echo ""
fi

echo "Building..."
if [ -n "$TARGET" ]; then
    rustup target add "$TARGET"
    cargo build --release --target "$TARGET"
    BUILT="target/$TARGET/release"
else
    cargo build --release
    BUILT="target/release"
fi
echo ""

# Ask the binary what it thinks it is before wrapping it up. The version
# reaches the compiler through the environment, so the box and its contents
# are stamped by two different steps, and a package labelled with one version
# holding a binary that answers with another is the one failure a green
# workflow would happily wave through.
#
# Only the build for this machine is asked, because a binary for another
# architecture cannot be run here to answer. It is the same source and the
# same variable, so the one that can speak vouches for the one that cannot.
if [ -n "$VERSION" ] && [ -z "$TARGET" ]; then
    STAMPED=$("$BUILT/$BINARY" --version 2>/dev/null || true)
    if [ "$STAMPED" != "toolmarks $VERSION" ]; then
        echo "The binary says '$STAMPED' but the tag is '$VERSION'."
        echo "Run 'cargo clean' and build again."
        exit 1
    fi
    echo "Stamped: $STAMPED"
    echo ""
fi

# Only this package is cleared out, not the whole folder, so that two runs
# on one machine leave two packages rather than one.
rm -rf "dist/$NAME" "dist/$NAME.zip" "dist/$NAME.tar.gz"
mkdir -p "dist/$NAME"
cp "$BUILT/$BINARY" "dist/$NAME/"
cp README.md LICENSE "dist/$NAME/"

cd dist
if [ "$BINARY" = "toolmarks.exe" ]; then
    # zip first: it is what the workflow has. powershell is the fallback for
    # building on Windows by hand, where zip is not standard.
    if command -v zip >/dev/null 2>&1; then
        zip -qr "$NAME.zip" "$NAME"
    else
        powershell -NoProfile -Command \
            "Compress-Archive -Path '$NAME' -DestinationPath '$NAME.zip' -Force" >/dev/null
    fi
else
    tar -czf "$NAME.tar.gz" "$NAME"
fi
cd ..

echo "Done."
ls -la dist/*.zip dist/*.tar.gz 2>/dev/null || true
