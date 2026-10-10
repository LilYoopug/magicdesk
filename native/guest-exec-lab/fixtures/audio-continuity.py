#!/usr/bin/env python3
"""Capture a selected PipeWire output without equating zero xruns with continuity.

Run inside the guest, with the environment of its live desktop/audio process.
Exact silence is evidence, not by itself an underrun diagnosis: use a known
continuous source and correlate the timestamps with client scheduling.
"""
import argparse
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time


class PhaseTimeline:
    def __init__(self, phases, rate):
        self.pending = []
        end = 0
        for name, seconds in phases:
            self.pending.append((name, end))
            end += seconds * rate
        self.markers = []

    def advance(self, frames, timestamp):
        added = []
        while self.pending and frames >= self.pending[0][1]:
            name, frame = self.pending.pop(0)
            added.append(dict(event='phase', name=name, frame=frame,
                              observedFrame=frames, observed=timestamp))
        self.markers.extend(added)
        return added


class PCMWindow:
    rate = 48000
    block_frames = 480
    block_bytes = block_frames * 2 * 2

    def __init__(self):
        self.pending = bytearray()
        self.frames = 0
        self.silent_from = None
        self.spans = []

    def feed(self, data, timestamp):
        self.pending.extend(data)
        consumed = 0
        while len(self.pending) - consumed >= self.block_bytes:
            block = self.pending[consumed:consumed + self.block_bytes]
            if self.frames >= 2 * self.rate and not any(block):
                if self.silent_from is None:
                    self.silent_from = (self.frames, timestamp)
            else:
                self.finish_span(timestamp)
            self.frames += self.block_frames
            consumed += self.block_bytes
        del self.pending[:consumed]

    def finish_span(self, timestamp):
        if self.silent_from is not None:
            frame, first = self.silent_from
            self.spans.append(dict(startFrame=frame, frames=self.frames-frame,
                                   firstObserved=first, lastObserved=timestamp))
            self.silent_from = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-pid', type=int, required=True)
    parser.add_argument('--target', required=True)
    parser.add_argument('--seconds', type=int, default=90)
    parser.add_argument('--phase', action='append', default=[], metavar='NAME:SECONDS',
                        help='Consecutive phases on one recorder connection; replaces --seconds')
    args = parser.parse_args()
    phases = []
    for value in args.phase:
        try:
            name, seconds = value.rsplit(':', 1)
            seconds = int(seconds)
            if not name or seconds <= 0:
                raise ValueError()
        except ValueError:
            parser.error('phase must be NAME:positive-seconds')
        phases.append((name, seconds))
    if phases:
        args.seconds = sum(seconds for _, seconds in phases)
    else:
        phases = [('capture', args.seconds)]
    if not 3 <= args.seconds <= 600:
        parser.error('seconds must be in 3..600')
    env = dict(entry.split('=', 1) for entry in
               Path(f'/proc/{args.env_pid}/environ').read_bytes().decode().split('\0') if '=' in entry)
    process = subprocess.Popen(['pw-record', '--target', args.target, '--properties',
        '{ stream.capture.sink = true }', '--raw', '--format', 's16', '--rate', '48000',
        '--channels', '2', '-'], env=env, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, bufsize=0)
    sel = selectors.DefaultSelector()
    sel.register(process.stdout, selectors.EVENT_READ)
    pcm = PCMWindow()
    start = last = time.monotonic()
    gaps = []
    timeline = PhaseTimeline(phases, pcm.rate)
    print(json.dumps(dict(event='recording', start=start, target=args.target)), flush=True)
    try:
        while pcm.frames < args.seconds * pcm.rate:
            # EVENT_WAIT: PCM/EOF; missing frames at the deadline fail the capture.
            remaining = start + args.seconds + 20 - time.monotonic()
            if remaining <= 0 or not sel.select(remaining):
                raise TimeoutError('PCM recording deadline')
            data = os.read(process.stdout.fileno(), 16384)
            stamp = time.monotonic()
            if not data:
                raise RuntimeError('recording ended before requested frame count')
            if pcm.frames and stamp-last > .08:
                gaps.append(dict(start=last, end=stamp))
            last = stamp
            pcm.feed(data, stamp)
            for marker in timeline.advance(pcm.frames, stamp):
                print(json.dumps(marker), flush=True)
        pcm.finish_span(last)
        if process.poll() is not None:
            raise RuntimeError('recorder exited before requested stop')
        process.send_signal(signal.SIGINT)
        # EVENT_WAIT: pw-record handles SIGINT and flushes; timeout cancels it.
        _, stderr = process.communicate(timeout=5)
        report = dict(target=args.target, start=start, end=last, frames=pcm.frames,
                      rate=pcm.rate, zeroSpans=pcm.spans, deliveryGaps80ms=gaps,
                      recorderExit=process.returncode, stoppedByClient=True,
                      phases=timeline.markers,
                      stderr=stderr.decode(errors='replace'))
        print(json.dumps(report), flush=True)
        # pw-cat reports success only for a drained playback stream; a requested
        # recording stop can exit 1 even after delivering every requested frame.
        if process.returncode not in (0, 1) or stderr:
            raise RuntimeError('recorder reported an unexpected stop')
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        sel.close()


if __name__ == '__main__':
    main()
