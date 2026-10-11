package io.github.mekhontsev.magicdesk;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/** An installation-local, non-exportable key, unrelated to MagicDesk's release/debug keys. */
record LauncherSigningIdentity(PrivateKey key, X509Certificate certificate) {
    static LauncherSigningIdentity load() throws Exception {
        String alias = "magicdesk.launcher.exports";
        var store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        if (!store.containsAlias(alias)) {
            var generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            generator.initialize(new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setKeySize(2048).setDigests(KeyProperties.DIGEST_SHA256)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1).build());
            generator.generateKeyPair();
        }
        return new LauncherSigningIdentity((PrivateKey) store.getKey(alias, null), (X509Certificate) store.getCertificate(alias));
    }

    String fingerprint() throws Exception {
        return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
    }
}
