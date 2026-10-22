#!/usr/bin/env python3
"""Apply documented engine network profiles to a dedicated test installation."""
import json
from pathlib import Path
import re
import shutil
import subprocess

assert shutil.which('nft'), 'Install nftables before selecting the nftables network profile'
podman = json.loads(subprocess.check_output(['podman', 'info', '--format', 'json'], text=True))
backend = podman['host']['networkBackendInfo']
assert backend['backend'] == 'netavark', 'The fixture exercises netavark networking'
dns = backend.get('dns', {}).get('path', '')
assert dns and Path(dns).is_file(), 'Install aardvark-dns for named container peers'

version = subprocess.check_output(['dockerd', '--version'], text=True)
major = int(re.search(r'version (\d+)', version).group(1))
config = {'ip6tables': False, 'storage-driver': 'overlay2', 'userland-proxy': False}
if major >= 29:
    config.update({'firewall-backend': 'nftables'})
else:
    iptables = subprocess.check_output(['iptables', '--version'], text=True)
    assert 'nf_tables' in iptables, 'The iptables profile requires the nftables frontend'
    config.update({'iptables': True})
path = Path('/etc/docker/daemon.json')
assert not path.exists() or json.loads(path.read_text()) == config, 'Refusing to overwrite another daemon configuration'
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(config, indent=2) + '\n')
path = Path('/etc/containers/containers.conf.d/90-shroot-fixture.conf')
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text('[network]\nfirewall_driver="nftables"\n')
print(json.dumps({'dockerVersion': version.strip(), 'docker': config, 'podmanFirewall': 'nftables'}))
