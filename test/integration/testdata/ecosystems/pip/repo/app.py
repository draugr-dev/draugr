import os
import subprocess


def ping(host):
    # ruleid: draugr-fixture-os-popen
    return os.popen("ping -c 1 " + host).read()


def ping_safely(host):
    # ok: draugr-fixture-os-popen
    return subprocess.run(["ping", "-c", "1", host], capture_output=True, check=False).stdout
