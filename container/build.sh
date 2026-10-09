#!/bin/sh
# Build the Directory Console image: test and package with Maven, gather the jar and its runtime
# dependencies, refuse anything of OpenText's, then docker build.
#   container/build.sh [tag]        default directory-console:<version from pom.xml>
set -e
HERE=$(cd "$(dirname "$0")/.." && pwd)
VER=$(sed -n 's#^    <version>\([^<]*\)</version>.*#\1#p' "$HERE/pom.xml" | head -1)
TAG=${1:-directory-console:$VER}
cd "$HERE"
mvn -B -q install
CTX="$HERE/container"
rm -rf "$CTX/artifacts" && mkdir -p "$CTX/artifacts/lib"
cp console-server/target/console.jar "$CTX/artifacts/console.jar"
cp console-server/target/lib/*.jar "$CTX/artifacts/lib/"
# the engine's jars are OpenText's and are never in the image (Phase 4 mounts the customer's at /engine)
for j in "$CTX"/artifacts/console.jar "$CTX"/artifacts/lib/*.jar; do
  if unzip -l "$j" | grep -qE ' com/novell/nds/dirxml/| com/netiq/| com/novell/ldap/'; then
    echo "ERROR: $j carries OpenText classes; not publishable" >&2
    exit 1
  fi
done
docker build -t "$TAG" "$CTX"
echo "built $TAG"
