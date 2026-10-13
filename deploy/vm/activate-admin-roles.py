#!/usr/bin/env python3
"""Pin and verify an API/UI-only release, restoring both pins on failure.

Run as root on synthetic-sherlock-host with the validated staged release directory.
Does not change current, schema, membership flags, workers or control.
"""
import datetime
import os
import pathlib
import signal
import subprocess
import sys
import time

os.umask(0o077)

def interrupted(signum, frame):
    raise RuntimeError("admin rollout interrupted; restoring component pins")

for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGALRM):
    signal.signal(sig, interrupted)
signal.alarm(120)
release = pathlib.Path(sys.argv[1]).resolve()
assert release.parent == pathlib.Path('/opt/sherlock/releases')
units = ['sherlock-api', 'sherlock-admin-ui']
for unit in units:
    assert (release / 'bin' / unit).is_file()
backup = pathlib.Path('/var/backups/sherlock') / ('admin-units-' + release.name)
backup.mkdir(mode=0o700)
old = {}
for unit in units:
    pin = pathlib.Path('/etc/systemd/system') / (unit + '.service.d/gp09-network-release.conf')
    assert pin.is_file()
    old[unit] = pin.read_bytes()
    (backup / (unit + '.conf')).write_bytes(old[unit])

def run(args):
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=40).stdout.strip()

def atomic_write(path, content):
    temporary = path.with_suffix('.gp11.tmp')
    temporary.write_bytes(content)
    temporary.replace(path)

def event(message):
    print(datetime.datetime.now(datetime.timezone.utc).isoformat(), message, flush=True)

changed = False
try:
    for unit in units:
        pin = pathlib.Path('/etc/systemd/system') / (unit + '.service.d/gp09-network-release.conf')
        changed = True
        atomic_write(pin, ('[Service]\nExecStart=\nExecStart=' + str(release / 'bin' / unit) + '\n').encode())
    run(['systemctl', 'daemon-reload'])
    # API first: the prior UI still uses compatible routes; the new UI requires
    # the shared-report endpoint. Control/collector leases keep their process.
    for unit in units:
        run(['systemctl', 'restart', unit])
        deadline = time.monotonic() + 12
        while True:
            pid = run(['systemctl', 'show', unit, '-p', 'MainPID', '--value'])
            if pid != '0' and pathlib.Path('/proc/' + pid + '/exe').exists():
                if pathlib.Path('/proc/' + pid + '/exe').resolve() == release / 'bin' / unit:
                    run(['systemctl', 'is-active', unit])
                    break
            if time.monotonic() > deadline:
                raise RuntimeError('admin executable verification failed')
            time.sleep(0.2)
        event(unit + ' PID=' + pid + ' executable=' + str(release / 'bin' / unit))
    event('ADMIN_ROLES_VERIFIED backup=' + str(backup))
except BaseException:
    if changed:
        for unit, content in old.items():
            atomic_write(pathlib.Path('/etc/systemd/system') / (unit + '.service.d/gp09-network-release.conf'), content)
        subprocess.run(['systemctl', 'daemon-reload'], check=False, timeout=40)
        subprocess.run(['systemctl', 'restart', *units], check=False, timeout=40)
        event('ADMIN_ROLES_ROLLED_BACK')
    raise
finally:
    signal.alarm(0)
