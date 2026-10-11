#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ -z "${MONTOYA_API_JAR:-}" ]]; then
  printf '%s\n' 'Set MONTOYA_API_JAR to a local public Montoya API JAR.' >&2
  exit 2
fi
java tools/Build.java "$MONTOYA_API_JAR"
java -ea -cp "build/classes:build/test-classes:$MONTOYA_API_JAR" org.bughunter.burp.ExtensionFixture
