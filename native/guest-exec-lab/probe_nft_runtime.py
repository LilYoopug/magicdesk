#!/usr/bin/env python3
"""Exercise a distribution's unmodified nft against a private Shroot ruleset.

Catalogue/transaction coverage includes iptables-nft CRUD and an xt NAT exchange.
The separate traffic fixture covers broader filtering/NAT behavior. Unsupported
expressions must fail without committing earlier batch changes.
"""
import argparse
import json
import socket
from pathlib import Path
import subprocess
import sys


def guest():
    report = {'commands': [], 'passed': False}

    def run(argv, text=None, success=True):
        # EVENT_WAIT: exact nft child completion; timeout fails the fixture.
        result = subprocess.run(argv, input=text, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=20)
        report['commands'].append({'argv': argv, 'input': text, 'exitCode': result.returncode,
                                   'stdout': result.stdout, 'stderr': result.stderr})
        if result.returncode and success:
            trace = subprocess.run(['strace', '-f', '-xx', '-s', '16384', '-e', 'trace=sendmsg,sendto,recvmsg', *argv],
                                   input=text, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            report['failureTrace'] = trace.stderr
        assert (result.returncode == 0) == success, report['commands'][-1]
        if success and argv[0].startswith('iptables'):
            assert not result.stderr, report['commands'][-1]
        return result.stdout

    def tables():
        ruleset = json.loads(run(['nft', '-j', 'list', 'ruleset']))
        return {(entry['table']['family'], entry['table']['name'])
                for entry in ruleset['nftables'] if 'table' in entry}

    try:
        run(['nft', '--version'])
        assert not tables()
        run(['nft', '-f', '-'], 'add table inet first\nadd table ip second\n')
        assert tables() == {('inet', 'first'), ('ip', 'second')}
        run(['nft', '-f', '-'], 'add table inet aborted\ncreate table inet first\n', success=False)
        assert tables() == {('inet', 'first'), ('ip', 'second')}
        run(['nft', '-f', '-'], 'add table inet unenforced\n'
            'add chain inet unenforced input { type filter hook input priority 0; policy accept; }\n'
            'add rule inet unenforced input limit rate 1/second drop\n', success=False)
        assert tables() == {('inet', 'first'), ('ip', 'second')}
        nested = json.loads(run(['unshare', '-n', 'nft', '-j', 'list', 'ruleset']))
        assert not any('table' in entry for entry in nested['nftables'])
        run(['nft', 'delete', 'table', 'inet', 'first'])
        assert tables() == {('ip', 'second')}
        run(['nft', 'flush', 'ruleset'])
        assert not tables()
        run(['nft', '-f', '-'], ''.join(f'add table ip table{i}\n' for i in range(150)))
        assert tables() == {('ip', f'table{i}') for i in range(150)}
        run(['nft', 'flush', 'ruleset'])
        assert not tables()
        run(['nft', '-f', '-'], 'add table inet mdfilter\n'
            'add chain inet mdfilter forward { type filter hook forward priority 0; policy accept; }\n'
            'add chain inet mdfilter post { type nat hook postrouting priority 100; policy accept; }\n'
            'add chain inet mdfilter subchain\n')
        for chain, expression in [
                ('forward', 'meta mark set meta mark | 0x2000'),
                ('forward', 'meta mark & 0x2000 == 0x2000 accept'),
                ('forward', 'fib daddr type local jump subchain'),
                ('forward', 'ct state invalid drop'),
                ('forward', 'ct mark set ct mark | 0x1000'),
                ('forward', 'iifname "br-test" oifname != "br-test" jump subchain'),
                ('forward', 'ip daddr 10.88.0.0/16 ct state related,established accept'),
                ('forward', 'ip saddr 10.88.0.0/16 meta l4proto { tcp, udp } th dport 53 accept'),
                ('post', 'ip daddr != 224.0.0.0/4 masquerade')]:
            run(['nft', '--debug', 'netlink', '-f', '-'], f'add rule inet mdfilter {chain} {expression}\n')
        rules = json.loads(run(['nft', '-j', 'list', 'ruleset']))
        assert sum('rule' in item for item in rules['nftables']) == 9
        run(['nft', '-f', '-'], 'add rule inet mdfilter forward log accept\n', success=False)
        assert json.loads(run(['nft', '-j', 'list', 'ruleset'])) == rules
        run(['nft', 'delete', 'chain', 'inet', 'mdfilter', 'subchain'], success=False)
        assert json.loads(run(['nft', '-j', 'list', 'ruleset'])) == rules
        run(['nft', 'delete', 'chain', 'inet', 'mdfilter', 'forward'])
        run(['nft', 'delete', 'chain', 'inet', 'mdfilter', 'subchain'])
        remaining = json.loads(run(['nft', '-j', 'list', 'ruleset']))
        assert sum('rule' in item for item in remaining['nftables']) == 1
        run(['nft', 'flush', 'ruleset'])
        run(['nft', '-f', '-'], 'add table ip maps\n'
            'add chain ip maps input { type filter hook input priority 0; policy accept; }\n'
            'add chain ip maps target\n'
            'add map ip maps interfaces { type ifname : verdict; }\n'
            'add element ip maps interfaces { "lo" : jump target }\n'
            'add rule ip maps input iifname vmap @interfaces\n'
            'add rule ip maps target fib saddr type local counter packets 7 bytes 99 accept\n')
        run(['nft', '-f', '-'], 'table ip maps {\n map interfaces { type ifname : verdict; }\n}\n'
            'add element ip maps interfaces { "eth0" : jump target }\n'
            'add rule ip maps input oifname vmap @interfaces\n')
        maps = json.loads(run(['nft', '-j', 'list', 'ruleset']))
        assert any(item.get('map', {}).get('name') == 'interfaces' for item in maps['nftables'])
        counters = [expr['counter'] for item in maps['nftables'] for expr in item.get('rule', {}).get('expr', []) if 'counter' in expr]
        assert counters == [{'packets': 7, 'bytes': 99}], counters
        run(['nft', '-f', '-'], 'add rule ip maps target iifname vmap @interfaces\n', success=False)
        assert json.loads(run(['nft', '-j', 'list', 'ruleset'])) == maps
        run(['nft', 'delete', 'chain', 'ip', 'maps', 'target'], success=False)
        run(['nft', 'delete', 'map', 'ip', 'maps', 'interfaces'], success=False)
        run(['nft', '-f', '-'], 'flush chain ip maps input\nflush map ip maps interfaces\n'
            'delete chain ip maps target\ndelete map ip maps interfaces\ndelete table ip maps\n')
        run(['iptables', '-t', 'nat', '-N', 'MD_TEST'])
        run(['iptables', '-t', 'nat', '-I', 'OUTPUT', '-d', '127.0.0.11', '-j', 'MD_TEST'])
        run(['iptables', '-t', 'nat', '-S'])
        run(['iptables', '-t', 'nat', '-D', 'OUTPUT', '-d', '127.0.0.11', '-j', 'MD_TEST'])
        run(['iptables', '-t', 'nat', '-X', 'MD_TEST'])
        run(['iptables', '-t', 'filter', '-A', 'OUTPUT', '-p', 'tcp', '--dport', '1234', '-j', 'ACCEPT'])
        run(['nft', 'flush', 'ruleset'])
        # Exercise xt NAT translation with real traffic, not just accepted ABI.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            server.settimeout(5)
            client.settimeout(5)
            server.bind(('127.0.0.11', 0))
            port = server.getsockname()[1]
            rule = ['-t', 'nat', '-A', 'OUTPUT', '-d', '127.0.0.11', '-p', 'udp', '--dport', '53',
                    '-j', 'DNAT', '--to-destination', f'127.0.0.11:{port}']
            run(['iptables', *rule])
            client.sendto(b'XT_NAT', ('127.0.0.11', 53))
            data, peer = server.recvfrom(100)
            assert data == b'XT_NAT'
            server.sendto(b'REPLY', peer)
            assert client.recvfrom(100) == (b'REPLY', ('127.0.0.11', 53))
            run(['iptables-save', '-c'])
            run(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', '127.0.0.11', '-p', 'udp',
                 '--sport', str(port), '-j', 'SNAT', '--to-source', ':53'])
            run(['iptables', '-t', 'nat', '-S'])
        before = json.loads(run(['nft', '-j', 'list', 'ruleset']))
        run(['iptables', '-t', 'nat', '-A', 'OUTPUT', '-p', 'udp', '--dport', '54', '-j',
             'DNAT', '--to-destination', '127.0.0.11:8000-8001'], success=False)
        assert json.loads(run(['nft', '-j', 'list', 'ruleset'])) == before
        run(['nft', 'flush', 'ruleset'])
        run(['nft', '-f', '-'], 'add table ip anonymous\n'
            'add chain ip anonymous input { type filter hook input priority 0; policy accept; }\n'
            'add rule ip anonymous input iifname vmap { "lo" : accept, "eth0" : drop }\n')
        run(['nft', '-j', 'list', 'ruleset'])
        run(['nft', '-f', '-'], 'add table ip unrelated\n')
        run(['nft', '-j', 'list', 'ruleset'])
        run(['nft', 'flush', 'ruleset'])
        report['passed'] = True
    except Exception as error:
        report['failure'] = repr(error)
    print('NFT_REPORT ' + json.dumps(report), flush=True)


def main():
    from test_oci_services import Suite
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('store')
    args = parser.parse_args()
    suite = Suite(Path('build/nft-results'), args.build)
    target = '/tmp/md-nft-' + suite.report['id']
    runner = [suite.runner, '--store', args.store, '--user', '0:0', '--network', 'routed']
    created = False
    try:
        suite.transport.upload(suite.client, Path(__file__), suite.base + '/probe.py')
        suite.command(runner + ['--', '/bin/mkdir', target], quiet=True)
        created = True
        output = suite.command(runner + ['--bind-ro', suite.base, target, '--deadline-seconds', '180', '--',
                                        '/usr/bin/python3', target + '/probe.py', '--guest'], quiet=True, timeout=200)
        reports = [line.removeprefix('NFT_REPORT ') for line in output.splitlines() if line.startswith('NFT_REPORT ')]
        assert len(reports) == 1, output[-2000:]
        report = json.loads(reports[0])
        suite.report['nftables'] = report
        assert report['passed'], report.get('failure')
        suite.report['passed'] = True
        print('PASS stock nft/iptables-nft: catalogue, rollback, verdict maps, chain counters, xt NAT and cleanup')
    finally:
        try:
            if created:
                suite.command(runner + ['--', '/bin/rmdir', target], quiet=True)
        finally:
            suite.finish()


if __name__ == '__main__':
    guest() if '--guest' in sys.argv else main()
