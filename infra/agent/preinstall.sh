#!/bin/sh
set -e
getent group wt-agent >/dev/null || groupadd --system wt-agent
getent passwd wt-agent >/dev/null || useradd --system --gid wt-agent --home-dir /var/lib/wt-agent --shell /usr/sbin/nologin wt-agent
