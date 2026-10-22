#!/usr/bin/env python3
"""Boot the kernel-contract initramfs through stock system libvirt and TCG."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET


def main():
    work = Path(sys.argv[1]).resolve()
    name = 'md-libvirt-' + uuid.uuid4().hex
    report = {'name': name, 'passed': False, 'commands': []}
    prefix = ['virsh', '-c', 'qemu:///system']
    defined = False

    def run(*args, required=True):
        result = subprocess.run([*prefix, *args], capture_output=True, text=True, timeout=90,
                                env={**os.environ, 'LC_ALL': 'C'})
        report['commands'].append(dict(args=args, code=result.returncode,
                                       stdout=result.stdout, stderr=result.stderr))
        if required:
            assert result.returncode == 0, report['commands'][-1]
        return result

    try:
        domain = ET.Element('domain', type='qemu')
        ET.SubElement(domain, 'name').text = name
        ET.SubElement(domain, 'memory', unit='MiB').text = '512'
        ET.SubElement(domain, 'vcpu').text = '2'
        cpu = ET.SubElement(domain, 'cpu', mode='custom', match='exact')
        ET.SubElement(cpu, 'model', fallback='forbid').text = 'cortex-a72'
        boot = ET.SubElement(domain, 'os')
        ET.SubElement(boot, 'type', arch='aarch64', machine='virt').text = 'hvm'
        ET.SubElement(boot, 'kernel').text = str(work / 'kernel')
        ET.SubElement(boot, 'initrd').text = str(work / 'initrd')
        ET.SubElement(boot, 'cmdline').text = 'console=ttyAMA0 rdinit=/init magicdesk.kernel_fixture=1'
        ET.SubElement(domain, 'on_poweroff').text = 'destroy'
        ET.SubElement(domain, 'on_crash').text = 'destroy'
        devices = ET.SubElement(domain, 'devices')
        ET.SubElement(devices, 'emulator').text = '/usr/bin/qemu-system-aarch64'
        serial = ET.SubElement(devices, 'serial', type='unix')
        console = str(work / 'serial.sock')
        ET.SubElement(serial, 'source', mode='bind', path=console)
        target = ET.SubElement(serial, 'target', type='system-serial', port='0')
        ET.SubElement(target, 'model', name='pl011')
        xml = work / 'domain.xml'
        ET.ElementTree(domain).write(xml, encoding='unicode')
        run('define', str(xml)); defined = True
        run('start', name, '--paused')
        assert run('domstate', name).stdout.strip() == 'paused'
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.settimeout(180)
            stream.connect(console)
            run('resume', name)
            deadline = time.monotonic() + 180
            chunks = []
            # EVENT_WAIT: guest serial EOF on QEMU exit; deadline fails a stalled VM.
            while True:
                stream.settimeout(max(0.001, deadline - time.monotonic()))
                data = stream.recv(65536)
                if not data:
                    break
                chunks.append(data)
            output = b''.join(chunks).decode(errors='replace')
            (work / 'serial.log').write_text(output)
            assert 'PASS kernel contract in VM status=0' in output, output[-4000:]
        assert run('domstate', name).stdout.strip() == 'shut off'
        report['passed'] = True
        print('PASS libvirt: define, paused start, serial, resume, kernel boot and poweroff', flush=True)
    finally:
        if defined:
            run('destroy', name, required=False)
            run('undefine', name)
        (work / 'report.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
