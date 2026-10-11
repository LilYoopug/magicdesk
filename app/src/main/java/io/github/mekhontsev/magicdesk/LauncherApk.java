package io.github.mekhontsev.magicdesk;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Map;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/** Bounded template packaging and APK v2 framing. All cryptography is supplied by Java/Android. */
final class LauncherApk {
    static final int MAX_BYTES = 2 * 1024 * 1024;
    private static final int RSA_SHA256 = 0x0103;
    private static final int CHUNK = 1024 * 1024;

    static byte[] assemble(InputStream template, String host, String packageName, String label, byte[] icon)
            throws IOException {
        var bytes = new ByteArrayOutputStream();
        var names = new HashSet<String>();
        int size = 0, icons = 0;
        try (var input = new ZipInputStream(template); var output = new ZipOutputStream(bytes)) {
            ZipEntry entry;
            while ((entry = input.getNextEntry()) != null) {
                String name = entry.getName();
                if (entry.isDirectory() || name.startsWith("META-INF/")) continue;
                if (!names.add(name) || names.size() > 64) throw new IOException("Invalid launcher template entries");
                byte[] data = input.readNBytes(MAX_BYTES + 1);
                size += data.length;
                if (size > MAX_BYTES) throw new IOException("Launcher template is too large");
                if (name.equals("AndroidManifest.xml")) data = LauncherManifest.replace(data, Map.of(
                        "io.github.mekhontsev.magicdesk.launchertemplate", packageName,
                        "MAGICDESK_LAUNCHER_LABEL", label, "MAGICDESK_TARGET_PACKAGE", host));
                // The template has exactly one image; AGP may shorten its resource path.
                else if (name.startsWith("res/") && name.endsWith(".png")) { data = icon; icons++; }
                if (data.length > MAX_BYTES) throw new IOException("Launcher resource is too large");
                var copy = new ZipEntry(name);
                copy.setMethod(ZipEntry.STORED);
                copy.setTime(315532800000L);
                copy.setSize(data.length);
                var crc = new CRC32(); crc.update(data); copy.setCrc(crc.getValue());
                // Android requires uncompressed, four-byte aligned resources.arsc on API 30+.
                int padding = -(bytes.size() + 30 + name.getBytes(StandardCharsets.UTF_8).length + 4) & 3;
                copy.setExtra(le(4 + padding).putShort((short) 0xd935).putShort((short) padding).array());
                output.putNextEntry(copy); output.write(data); output.closeEntry();
            }
        }
        if (icons != 1 || !names.containsAll(java.util.List.of("AndroidManifest.xml", "classes.dex", "resources.arsc"))
                || bytes.size() > MAX_BYTES) throw new IOException("Incomplete launcher template");
        return bytes.toByteArray();
    }

    static byte[] sign(byte[] unsigned, PrivateKey key, X509Certificate certificate)
            throws IOException, GeneralSecurityException {
        if (unsigned.length < 22 || unsigned.length > MAX_BYTES) throw new IOException("Invalid launcher ZIP");
        // Our ZIP writer emits neither a comment nor ZIP64. Reject anything outside that contract.
        var zip = ByteBuffer.wrap(unsigned).order(ByteOrder.LITTLE_ENDIAN);
        int end = unsigned.length - 22;
        int directory = zip.getInt(end + 16), directorySize = zip.getInt(end + 12);
        if (zip.getInt(end) != 0x06054b50 || zip.getShort(end + 20) != 0 || zip.getInt(end + 4) != 0
                || zip.getShort(end + 8) != zip.getShort(end + 10) || directory < 0 || directorySize < 0
                || (long) directory + directorySize != end) throw new IOException("Unsupported launcher ZIP layout");
        byte[] digest = contentDigest(unsigned, directory, end);
        byte[] signedData = concat(sequence(concat(integer(RSA_SHA256), field(digest))),
                sequence(certificate.getEncoded()), field(new byte[0]));
        var signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(key); signer.update(signedData);
        byte[] signature = signer.sign();
        var verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(certificate); verifier.update(signedData);
        if (!verifier.verify(signature)) throw new GeneralSecurityException("Launcher signing key does not match its certificate");
        byte[] value = sequence(concat(field(signedData), sequence(concat(integer(RSA_SHA256), field(signature))),
                field(certificate.getPublicKey().getEncoded())));
        int blockSize = 8 + 8 + 4 + value.length + 8 + 16;
        var block = le(blockSize).putLong(blockSize - 8).putLong(4L + value.length).putInt(0x7109871a)
                .put(value).putLong(blockSize - 8).put("APK Sig Block 42".getBytes(StandardCharsets.US_ASCII)).array();
        var result = le(unsigned.length + blockSize).put(unsigned, 0, directory).put(block)
                .put(unsigned, directory, unsigned.length - directory);
        result.putInt(end + blockSize + 16, directory + blockSize);
        return result.array();
    }

    private static byte[] contentDigest(byte[] bytes, int directory, int end) throws GeneralSecurityException {
        int[] bounds = {0, directory, end, bytes.length};
        int chunks = 0;
        for (int i = 0; i < 3; i++) chunks += (bounds[i + 1] - bounds[i] + CHUNK - 1) / CHUNK;
        var total = MessageDigest.getInstance("SHA-256");
        total.update((byte) 0x5a); total.update(integer(chunks));
        var part = MessageDigest.getInstance("SHA-256");
        for (int i = 0; i < 3; i++) for (int at = bounds[i]; at < bounds[i + 1]; at += CHUNK) {
            int length = Math.min(CHUNK, bounds[i + 1] - at);
            part.update((byte) 0xa5); part.update(integer(length)); part.update(bytes, at, length);
            total.update(part.digest());
        }
        return total.digest();
    }

    private static ByteBuffer le(int bytes) { return ByteBuffer.allocate(bytes).order(ByteOrder.LITTLE_ENDIAN); }
    private static byte[] integer(int value) { return le(4).putInt(value).array(); }
    private static byte[] field(byte[] bytes) { return concat(integer(bytes.length), bytes); }
    private static byte[] sequence(byte[] bytes) { return field(field(bytes)); }
    private static byte[] concat(byte[]... parts) {
        var output = new ByteArrayOutputStream();
        for (byte[] part : parts) output.writeBytes(part);
        return output.toByteArray();
    }
    private LauncherApk() { }
}
