#!/usr/bin/env python3
"""Exercise stock machinectl boot, shell, services, veth IO and restart after exit."""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import threading
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('machine')
    parser.add_argument('report', type=Path)
    args = parser.parse_args()
    assert re.fullmatch(r'[a-zA-Z0-9_-]+', args.machine)
    machine = args.machine
    unit = 'systemd-nspawn@' + machine + '.service'
    report = dict(machine=machine, commands=[], rounds=[], passed=False)
    env = {**os.environ, 'LC_ALL': 'C'}

    def run(*argv, required=True, timeout=60):
        print('RUN', argv, flush=True)
        result = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=timeout)
        report['commands'].append(dict(argv=argv, code=result.returncode,
                                       stdout=result.stdout, stderr=result.stderr))
        print(result.stdout + result.stderr, end='', flush=True)
        if required:
            assert result.returncode == 0, report['commands'][-1]
        return result

    def service(*argv):
        return run('systemd-run', '-M', machine, '--wait', '--pipe', '--collect', *argv)

    def ready():
        deadline = time.monotonic() + 90
        while True:
            result = run('systemctl', '-M', machine, 'is-system-running', '--wait', required=False)
            if result.returncode == 0:
                assert result.stdout.strip() == 'running'
                return
            # A started nspawn unit precedes the nested manager's bus listener.
            # Retry only connection readiness, never a failed/degraded boot.
            assert 'Failed to connect' in result.stderr and any(
                text in result.stderr for text in ('No such file or directory', 'Connection refused'))
            assert time.monotonic() < deadline, 'Nested system bus did not become ready'
            assert run('systemctl', 'is-active', unit).stdout.strip() == 'active'
            # EVENT_WAIT: bounded retry backoff for nested bus creation, not a settling assumption.
            threading.Event().wait(0.1)

    assert run('systemctl', 'is-active', unit, required=False).returncode != 0, 'Machine must be idle'
    started = False
    try:
        report['versions'] = run('systemd-nspawn', '--version').stdout
        report['template'] = run('systemctl', 'cat', unit).stdout
        for repeat in range(3):
            record = dict(round=repeat, passed=False)
            report['rounds'].append(record)
            started = True
            run('machinectl', 'start', machine, timeout=180)
            assert run('systemctl', 'is-active', unit).stdout.strip() == 'active'
            ready()
            properties = dict(line.split('=', 1) for line in run('machinectl', 'show', machine).stdout.splitlines()
                              if '=' in line)
            leader = int(properties['Leader'])
            assert properties['State'] == 'running' and leader > 1
            record['machine'] = properties
            result = service('/bin/sh', '-ec', 'test "$(cat /proc/1/comm)" = systemd; '
                             'test "$(id -u)" = 0; cat /proc/self/uid_map; echo NS_SERVICE_OK')
            assert 'NS_SERVICE_OK' in result.stdout
            mapping = next(line for line in result.stdout.splitlines() if len(line.split()) == 3)
            inside, outside, count = map(int, mapping.split())
            assert inside == 0 and outside > 0 and count >= 65536
            record['uidMap'] = mapping
            marker = '/run/md-shell-' + uuid.uuid4().hex
            argv = ['machinectl', 'shell', 'root@' + machine, '/bin/sh', '-ec',
                    'printf shell-ok >' + marker + '; echo NS_SHELL_OK']
            # EVENT_WAIT: retain stdin until the remote command exits, not EOF at startup.
            with subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True, env=env) as process:
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise
                output = process.stdout.read()
                report['commands'].append(dict(argv=argv, code=process.returncode, stdout=output))
                assert process.returncode == 0 and 'NS_SHELL_OK' in output, output
            assert service('/bin/cat', marker).stdout == 'shell-ok'
            links = json.loads(service('/usr/bin/env', 'ip', '-j', 'link', 'show', 'host0').stdout)
            assert links[0]['ifname'] == 'host0'
            peer_index = int(service('/bin/cat', '/sys/class/net/host0/iflink').stdout)
            outer = next(link for link in json.loads(run('ip', '-j', 'link').stdout)
                         if link['ifindex'] == peer_index)
            interface = outer['ifname']
            run('ip', 'address', 'add', '10.231.247.1/30', 'dev', interface)
            run('ip', 'link', 'set', interface, 'up')
            service('/usr/bin/env', 'ip', 'address', 'add', '10.231.247.2/30', 'dev', 'host0')
            service('/usr/bin/env', 'ip', 'link', 'set', 'host0', 'up')
            errors = []

            def echo(stream):
                try:
                    for _ in range(20):
                        if stream.type == socket.SOCK_STREAM:
                            connection, _ = stream.accept()
                            with connection:
                                connection.settimeout(30)
                                connection.sendall(connection.recv(64))
                        else:
                            data, peer = stream.recvfrom(64)
                            stream.sendto(data, peer)
                except Exception as error:
                    errors.append(repr(error))

            with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
                for stream in (tcp, udp):
                    stream.bind(('10.231.247.1', 0))
                    stream.settimeout(30)
                tcp.listen(4)
                threads = [threading.Thread(target=echo, args=(stream,), daemon=True) for stream in (tcp, udp)]
                for thread in threads:
                    thread.start()
                endpoints = [(int(socket.SOCK_STREAM), tcp.getsockname()[1]),
                             (int(socket.SOCK_DGRAM), udp.getsockname()[1])]
                code = ('import socket\nfor kind,port in ' + repr(endpoints) + ':\n'
                        ' for i in range(20):\n'
                        '  with socket.socket(type=kind) as s:\n'
                        '   s.settimeout(5); s.connect(("10.231.247.1",port)); s.sendall(b"nspawn"); '
                        'assert s.recv(64)==b"nspawn"\nprint("NS_NETWORK_OK")')
                try:
                    assert 'NS_NETWORK_OK' in service('/usr/bin/python3', '-c', code).stdout
                finally:
                    for thread in threads:
                        thread.join(timeout=35)
                assert not errors and not any(thread.is_alive() for thread in threads), errors
            record['network'] = dict(tcp=20, udp=20, interface=interface)
            if repeat == 1:
                run('machinectl', '--kill-whom=leader', '--signal=KILL', 'kill', machine)
                deadline = time.monotonic() + 90
                while True:
                    state = run('systemctl', 'show', '-p', 'ActiveState', '--value', unit).stdout.strip()
                    if state in ('inactive', 'failed'):
                        break
                    assert time.monotonic() < deadline, 'Killed container did not retire'
                    # EVENT_WAIT: bounded unit-state reconciliation after abrupt leader death.
                    threading.Event().wait(0.1)
                result = run('systemctl', 'show', '-p', 'Result', '--value', unit).stdout.strip()
                assert result in ('exit-code', 'signal'), result
                record['exit'] = 'killed'
                run('systemctl', 'reset-failed', unit)
            else:
                run('machinectl', 'poweroff', machine)
                # EVENT_WAIT: systemd stop job waits for guest poweroff and ExecStopPost cleanup.
                run('systemctl', 'stop', unit, timeout=180)
                assert run('systemctl', 'show', '-p', 'Result', '--value', unit).stdout.strip() == 'success'
                record['exit'] = 'poweroff'
            started = False
            assert run('systemctl', 'show', '-p', 'ActiveState', '--value', unit).stdout.strip() == 'inactive'
            assert run('machinectl', 'show', machine, required=False).returncode != 0
            assert not Path('/proc/' + str(leader)).exists()
            assert not any(link['ifindex'] == peer_index for link in json.loads(run('ip', '-j', 'link').stdout))
            record['passed'] = True
        report['passed'] = True
    except Exception as error:
        report['failure'] = repr(error)
        run('journalctl', '-u', unit, '-n', '100', '--no-pager', required=False)
        raise
    finally:
        try:
            if started:
                run('machinectl', 'poweroff', machine, required=False)
                run('systemctl', 'stop', unit, timeout=180)
        finally:
            args.report.write_text(json.dumps(report, indent=2) + '\n')
            print('NSPAWN_REPORT ' + str(args.report) + ' passed=' + str(report['passed']), flush=True)


if __name__ == '__main__':
    main()
