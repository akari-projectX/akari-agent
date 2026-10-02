# Throw-away systemd node for scripts/systemd-test/run.sh (W18): Debian 13,
# systemd 257 as PID 1. Run privileged with --cgroupns=host, the host cgroup
# fs, and --tmpfs /var/lib/private:mode=0700 (overlayfs cannot be idmapped:
# without the tmpfs systemd would not mount the StateDirectory
# noexec,idmapped as on a real VPS). Same image as akari-panel's
# scripts/install-test. Test use only.
FROM debian:13
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      systemd systemd-sysv curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && systemctl mask systemd-firstboot.service getty.target console-getty.service \
      systemd-logind.service systemd-networkd.service systemd-resolved.service \
      systemd-timesyncd.service
STOPSIGNAL SIGRTMIN+3
# systemd credentials (LoadCredential=, used by the agent unit) need shared
# mount propagation; docker makes / private.
CMD ["/bin/sh", "-c", "mount --make-rshared / && exec /sbin/init"]
