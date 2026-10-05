# Throw-away Alpine node for scripts/openrc-test/run.sh (W32): Alpine 3.22,
# OpenRC started as the container's init system (rc_sys="docker"; run with
# --init so something reaps what supervise-daemon leaves) and curl. Run it
# privileged: the agent's OpenRC script bind-mounts its state directory
# noexec, as on a VM. The same image as akari-panel's
# scripts/install-test-alpine (its smoke installs an Alpine node with the
# one-line installer). Test use only.
FROM alpine:3.22
RUN apk add --no-cache openrc curl ca-certificates \
 && sed -i 's/^#\?rc_sys=.*/rc_sys="docker"/' /etc/rc.conf
CMD ["/bin/sh", "-c", "mkdir -p /run/openrc && touch /run/openrc/softlevel && openrc default >/dev/null 2>&1; exec sleep infinity"]
