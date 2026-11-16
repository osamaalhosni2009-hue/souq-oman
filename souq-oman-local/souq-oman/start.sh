#!/bin/sh
cd "$(dirname "$0")"
command -v node >/dev/null 2>&1 || { echo "Install Node.js (LTS) first: https://nodejs.org"; exit 1; }
node server.js
