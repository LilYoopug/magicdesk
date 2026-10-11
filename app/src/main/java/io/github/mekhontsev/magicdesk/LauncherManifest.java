package io.github.mekhontsev.magicdesk;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Map;

/** Rewrites only the string pool of our compiled manifest; XML nodes and resource IDs stay intact. */
final class LauncherManifest {
    private static final int MAX_BYTES = 256 * 1024;

    static byte[] replace(byte[] xml, Map<String, String> replacements) throws IOException {
        if (xml.length < 8 || xml.length > MAX_BYTES) throw invalid();
        var in = ByteBuffer.wrap(xml).order(ByteOrder.LITTLE_ENDIAN);
        if (in.getInt(0) != 0x00080003 || in.getInt(4) != xml.length) throw invalid();
        int at = 8, pool = -1, size = 0;
        while (at < xml.length) {
            if (xml.length - at < 8) throw invalid();
            int length = in.getInt(at + 4), header = Short.toUnsignedInt(in.getShort(at + 2));
            if (header < 8 || length < header || length > xml.length - at) throw invalid();
            if (in.getShort(at) == 1) {
                if (pool >= 0) throw invalid();
                pool = at; size = length;
            }
            at += length;
        }
        if (pool < 0 || in.getShort(pool + 2) != 28 || size < 28) throw invalid();
        int count = in.getInt(pool + 8), styles = in.getInt(pool + 12);
        int flags = in.getInt(pool + 16), start = in.getInt(pool + 20);
        if (count < 0 || count > 4096 || styles != 0 || in.getInt(pool + 24) != 0
                || start != 28 + count * 4 || start > size) throw invalid();
        boolean utf8 = (flags & 0x100) != 0;
        var strings = new ByteArrayOutputStream();
        var offsets = new int[count];
        var found = new HashSet<String>();
        for (int i = 0; i < count; i++) {
            int offset = in.getInt(pool + 28 + i * 4);
            if (offset < 0 || offset >= size - start) throw invalid();
            var value = ByteBuffer.wrap(xml, pool + start + offset, size - start - offset)
                    .slice().order(ByteOrder.LITTLE_ENDIAN);
            String text = readString(value, utf8);
            if (replacements.containsKey(text)) { found.add(text); text = replacements.get(text); }
            if (text == null || text.indexOf('\0') >= 0 || text.length() > 16383) throw invalid();
            offsets[i] = strings.size();
            // Always emit UTF-16, retaining exactly the same indices for XML/resource-map references.
            strings.write(text.length() & 255); strings.write(text.length() >>> 8);
            strings.writeBytes(text.getBytes(StandardCharsets.UTF_16LE));
            strings.write(0); strings.write(0);
        }
        if (!found.equals(replacements.keySet())) throw new IOException("Launcher template markers are missing");
        while ((strings.size() & 3) != 0) strings.write(0);
        int updatedSize = start + strings.size(), total = xml.length - size + updatedSize;
        if (total > MAX_BYTES) throw invalid();
        var out = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN);
        out.put(xml, 0, pool);
        out.putShort((short) 1).putShort((short) 28).putInt(updatedSize).putInt(count).putInt(0);
        out.putInt(flags & ~0x101).putInt(start).putInt(0); // Order may change; clear SORTED and UTF8.
        for (int offset : offsets) out.putInt(offset);
        out.put(strings.toByteArray()).put(xml, pool + size, xml.length - pool - size);
        out.putInt(4, total);
        return out.array();
    }

    private static String readString(ByteBuffer in, boolean utf8) throws IOException {
        try {
            int characters = length(in, utf8), bytes = utf8 ? length(in, true) : Math.multiplyExact(characters, 2);
            if (bytes < 0 || bytes > in.remaining() - (utf8 ? 1 : 2)) throw invalid();
            byte[] data = new byte[bytes]; in.get(data);
            if (utf8 ? in.get() != 0 : in.getShort() != 0) throw invalid();
            String result = new String(data, utf8 ? StandardCharsets.UTF_8 : StandardCharsets.UTF_16LE);
            if (result.length() != characters) throw invalid();
            return result;
        } catch (java.nio.BufferUnderflowException | ArithmeticException error) { throw invalid(); }
    }

    private static int length(ByteBuffer in, boolean utf8) {
        int first = utf8 ? Byte.toUnsignedInt(in.get()) : Short.toUnsignedInt(in.getShort());
        int flag = utf8 ? 0x80 : 0x8000;
        return (first & flag) == 0 ? first : utf8
                ? ((first & 0x7f) << 8) | Byte.toUnsignedInt(in.get())
                : ((first & 0x7fff) << 16) | Short.toUnsignedInt(in.getShort());
    }

    private static IOException invalid() { return new IOException("Invalid launcher manifest template"); }
    private LauncherManifest() { }
}
