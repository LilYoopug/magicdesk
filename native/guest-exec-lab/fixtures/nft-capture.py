#!/usr/bin/python3
"""Fixture-only capture of nft input; the distribution's nft applies it unchanged."""
import json
import os
from pathlib import Path
import subprocess
import sys

args = sys.argv[1:]
reading = any(value in ('-f', '--file') and i + 1 < len(args) and args[i + 1] == '-'
              for i, value in enumerate(args))
data = sys.stdin.buffer.read() if reading else None
directory = Path(os.environ['MD_NFT_CAPTURE'])
directory.mkdir(parents=True, exist_ok=True)
record = {'args': args, 'input': data.decode() if data is not None else None}
(directory / (str(os.getpid()) + '.json')).write_text(json.dumps(record, indent=2))
result = subprocess.run(['/usr/bin/nft', *args], input=data,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
record.update(code=result.returncode, stdout=result.stdout.decode(errors='replace'),
              stderr=result.stderr.decode(errors='replace'))
if result.returncode and data is not None:
    check = subprocess.run(['/usr/bin/nft', '--check', '--debug=netlink', *args], input=data,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    record['debug'] = (check.stdout + check.stderr).decode(errors='replace')
(directory / (str(os.getpid()) + '.json')).write_text(json.dumps(record, indent=2))
sys.stdout.buffer.write(result.stdout)
sys.stderr.buffer.write(result.stderr)
sys.exit(result.returncode)
