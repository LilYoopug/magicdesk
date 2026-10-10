#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('audio_continuity',
    Path(__file__).with_name('fixtures') / 'audio-continuity.py')
audio = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audio)


class ContinuityTest(unittest.TestCase):
    def test_fragmented_frames_and_warmup(self):
        pcm = audio.PCMWindow()
        size = pcm.block_bytes
        pcm.feed(bytes(200 * size), 10)
        self.assertEqual(pcm.spans, [])
        pcm.feed(bytes(3 * size - 1), 11)
        pcm.feed(b'\0' + b'\1' * size, 12)
        self.assertEqual(pcm.frames, 204 * pcm.block_frames)
        self.assertEqual(pcm.spans, [dict(startFrame=96000, frames=1440,
                                        firstObserved=11, lastObserved=12)])
        self.assertEqual(pcm.pending, b'')

    def test_quiet_is_not_zero_and_terminal_span(self):
        pcm = audio.PCMWindow()
        size = pcm.block_bytes
        pcm.feed(b'\1' * (200 * size), 1)
        pcm.feed(b'\1' + bytes(size - 1), 2)
        pcm.feed(bytes(size + 7), 3)
        pcm.finish_span(4)
        self.assertEqual(pcm.spans[0]['startFrame'], 201 * pcm.block_frames)
        self.assertEqual(pcm.spans[0]['frames'], pcm.block_frames)
        self.assertEqual(len(pcm.pending), 7)
        pcm.finish_span(5)
        self.assertEqual(len(pcm.spans), 1)


if __name__ == '__main__':
    unittest.main()
