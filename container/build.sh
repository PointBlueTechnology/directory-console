#!/bin/sh
# Build the Directory Console image: build and test the web UI, test and package with Maven (the UI
# goes into the jar), gather the jar and its runtime dependencies, refuse anything of OpenText's,
# then docker build.
#   container/build.sh [tag]        default directory-console:<version from pom.xml>
#   container/build.sh --artifacts  everything but the docker build (CI builds and pushes the image itself)
set -e
HERE=$(cd "$(dirname "$0")/.." && pwd)
VER=$(sed -n 's#^    <version>\([^<]*\)</version>.*#\1#p' "$HERE/pom.xml" | head -1)
ONLY_ARTIFACTS=
if [ "$1" = "--artifacts" ]; then ONLY_ARTIFACTS=1; shift; fi
TAG=${1:-directory-console:$VER}
cd "$HERE"
(cd console-web && npm ci --ignore-scripts --no-audit --no-fund && npm test && npm run build)
mvn -B -q clean install
unzip -l console-server/target/console.jar | grep -q ' web/index.html' || { echo "ERROR: the web UI is not in console.jar" >&2; exit 1; }
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
if [ -n "$ONLY_ARTIFACTS" ]; then echo "artifacts ready in $CTX/artifacts"; exit 0; fi
docker build -t "$TAG" "$CTX"
echo "built $TAG"
