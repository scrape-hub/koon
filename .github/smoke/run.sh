#!/bin/bash
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
artifacts=$(cd "$1" && pwd)
platform=$2
wheel_platform=$3
cli=$4
shift 4

work=$(mktemp -d)
mkdir -p "$work/www"
printf ok > "$work/www/ok"

cp "$artifacts/koon.$platform.node" "crates/node/npm/$platform/"
(cd "crates/node/npm/$platform" && npm pack --silent --pack-destination "$work" >/dev/null)
(cd crates/node && npm pack --silent --pack-destination "$work" >/dev/null)
cp "$here/node.cjs" "$here/python.py" "$artifacts"/*-$wheel_platform.whl "$artifacts/$cli" "$work/"
chmod +x "$work/$cli"
ls "$work"

node_test='mkdir -p /tmp/t && cd /tmp/t
  npm install --silent --no-audit --no-fund "$W"/koonjs-[0-9]*.tgz "$W"/koonjs-"$PLATFORM"-*.tgz
  cp "$W/node.cjs" . && node node.cjs'
python_test='tag=$(python -c "import sys, sysconfig; print(\"cp%d%dt\" % sys.version_info[:2] if sysconfig.get_config_var(\"Py_GIL_DISABLED\") else \"abi3\")")
  python -m venv "$W/venv-$tag"
  py="$W/venv-$tag/bin/python"; [ -x "$py" ] || py="$W/venv-$tag/Scripts/python"
  "$py" -m pip install --quiet "$W"/*-"$tag"-*.whl && "$py" "$W/python.py"'
cli_test='out=$("$W/$CLI" -b chrome http://127.0.0.1:8471/ok) && [ "$out" = ok ] && echo "koon CLI: ok"'

export W="$work" PLATFORM="$platform" CLI="$cli"
py=$(command -v python3 || command -v python)
"$py" -m http.server 8471 --bind 127.0.0.1 --directory "$work/www" >/dev/null 2>&1 &
server=$!
trap 'kill $server' EXIT
sleep 2

if [ $# -eq 0 ]; then
  if [ "${ONLY:-}" = python ]; then
    bash -ec "$python_test"
  else
    for test in "$node_test" "$python_test" "$cli_test"; do
      bash -ec "$test"
    done
  fi
  exit 0
fi
for image in "$@"; do
  echo "== $image"
  case "$image" in
    node:*) tests=("$node_test" "$cli_test") ;;
    python:*) tests=("$python_test" "$cli_test") ;;
    *) tests=("$cli_test") ;;
  esac
  for test in "${tests[@]}"; do
    docker run --rm --network host -e W=/w -e PLATFORM -e CLI -v "$work:/w" "$image" sh -ec "$test"
  done
done
