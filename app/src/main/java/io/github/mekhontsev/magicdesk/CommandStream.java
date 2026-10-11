package io.github.mekhontsev.magicdesk;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;

/** Owned non-PTY command channel. Closing it revokes the relay's process ownership. */
interface CommandStream extends Closeable {
    InputStream inputStream() throws IOException;
    void writeLine(String line) throws IOException;
    @Override void close();
}
