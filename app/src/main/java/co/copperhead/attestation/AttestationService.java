package co.copperhead.attestation;

import co.copperhead.attestation.attestation.AuthorizationList;
import co.copperhead.attestation.attestation.Attestation;
import co.copperhead.attestation.attestation.AttestationApplicationId;
import co.copperhead.attestation.attestation.AttestationPackageInfo;
import co.copperhead.attestation.attestation.RootOfTrust;

import com.google.common.io.BaseEncoding;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.os.AsyncTask;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;

import java.io.ByteArrayInputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import java.security.cert.X509Certificate;

import static android.security.keystore.KeyProperties.DIGEST_SHA256;
import static android.security.keystore.KeyProperties.KEY_ALGORITHM_EC;

// TODO: switch to IntentService to queue up requests
public class AttestationService extends AsyncTask<Object, String, Void> {
    private static final String KEY_PERSISTENT_CHALLENGE = "persistent_challenge";
    private static final String KEY_PINNED_CERTIFICATE = "pinned_certificate";
    private static final String KEY_PINNED_CERTIFICATE_LENGTH = "pinned_certificate_length";
    private static final String KEY_PINNED_DEVICE = "pinned_device";
    private static final String KEY_PINNED_OS_VERSION = "pinned_os_version";
    private static final String KEY_PINNED_OS_PATCH_LEVEL = "pinned_os_patch_level";

    private static final String GOOGLE_ROOT_CERTIFICATE =
            "-----BEGIN CERTIFICATE-----\n"
                    + "MIIFYDCCA0igAwIBAgIJAOj6GWMU0voYMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV"
                    + "BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTYwNTI2MTYyODUyWhcNMjYwNTI0MTYy"
                    + "ODUyWjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B"
                    + "AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS"
                    + "Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7"
                    + "tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj"
                    + "nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq"
                    + "C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ"
                    + "oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O"
                    + "JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg"
                    + "sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi"
                    + "igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M"
                    + "RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E"
                    + "aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um"
                    + "AGMCAwEAAaOBpjCBozAdBgNVHQ4EFgQUNmHhAHyIBQlRi0RsR/8aTMnqTxIwHwYD"
                    + "VR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwDwYDVR0TAQH/BAUwAwEB/zAO"
                    + "BgNVHQ8BAf8EBAMCAYYwQAYDVR0fBDkwNzA1oDOgMYYvaHR0cHM6Ly9hbmRyb2lk"
                    + "Lmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC8wDQYJKoZIhvcNAQELBQAD"
                    + "ggIBACDIw41L3KlXG0aMiS//cqrG+EShHUGo8HNsw30W1kJtjn6UBwRM6jnmiwfB"
                    + "Pb8VA91chb2vssAtX2zbTvqBJ9+LBPGCdw/E53Rbf86qhxKaiAHOjpvAy5Y3m00m"
                    + "qC0w/Zwvju1twb4vhLaJ5NkUJYsUS7rmJKHHBnETLi8GFqiEsqTWpG/6ibYCv7rY"
                    + "DBJDcR9W62BW9jfIoBQcxUCUJouMPH25lLNcDc1ssqvC2v7iUgI9LeoM1sNovqPm"
                    + "QUiG9rHli1vXxzCyaMTjwftkJLkf6724DFhuKug2jITV0QkXvaJWF4nUaHOTNA4u"
                    + "JU9WDvZLI1j83A+/xnAJUucIv/zGJ1AMH2boHqF8CY16LpsYgBt6tKxxWH00XcyD"
                    + "CdW2KlBCeqbQPcsFmWyWugxdcekhYsAWyoSf818NUsZdBWBaR/OukXrNLfkQ79Iy"
                    + "ZohZbvabO/X+MVT3rriAoKc8oE2Uws6DF+60PV7/WIPjNvXySdqspImSN78mflxD"
                    + "qwLqRBYkA3I75qppLGG9rp7UCdRjxMl8ZDBld+7yvHVgt1cVzJx9xnyGCC23Uaic"
                    + "MDSXYrB4I4WHXPGjxhZuCuPBLTdOLU8YRvMYdEvYebWHMpvwGCF6bAx3JBpIeOQ1"
                    + "wDB5y0USicV3YgYGmi+NZfhA4URSh77Yd6uuJOJENRaNVTzk\n"
                    + "-----END CERTIFICATE-----";

    private static final String COPPERHEADOS_FINGERPRINT_TAIMEN =
            "815DCBA82BAC1B1758211FF53CAA0B6883CB6C901BE285E1B291C8BDAA12DF75";
    private static final String COPPERHEADOS_FINGERPRINT_WALLEYE =
            "36D067F8517A2284781B99A2984966BFF02D3F47310F831FCDCC4D792426B6DF";

    private final TextView view;

    AttestationService(TextView view) {
        this.view = view;
    }

    @Override
    protected Void doInBackground(Object... params) {
        try {
            testAttestation((Context) params[0]);
        } catch (Exception e) {
            StringWriter s = new StringWriter();
            e.printStackTrace(new PrintWriter(s));
            publishProgress(s.toString());
        }
        return null;
    }

    @Override
    protected void onProgressUpdate(String... values) {
        for (String value : values) {
            view.append(value);
        }
    }

    private static byte[] getChallenge() {
        final SecureRandom random = new SecureRandom();
        final byte[] challenge = new byte[32];
        random.nextBytes(challenge);
        return challenge;
    }

    private static class Verified {
        final String device;
        final int osVersion;
        final int osPatchLevel;

        Verified(final String device, final int osVersion, final int osPatchLevel) {
            this.device = device;
            this.osVersion = osVersion;
            this.osPatchLevel = osPatchLevel;
        }
    }

    private static Verified verifyAttestation(final Certificate certificates[], final byte[] challenge)
            throws GeneralSecurityException {

        verifyCertificateSignatures(certificates);

        // check that the root certificate is the Google key attestation root
        final X509Certificate secureRoot = (X509Certificate) CertificateFactory
                .getInstance("X.509").generateCertificate(
                        new ByteArrayInputStream(GOOGLE_ROOT_CERTIFICATE.getBytes()));
        final X509Certificate rootCert = (X509Certificate) certificates[certificates.length - 1];
        if (!Arrays.equals(secureRoot.getEncoded(), rootCert.getEncoded())) {
            throw new GeneralSecurityException("root certificate is not the Google key attestation root");
        }

        final Attestation attestation = new Attestation((X509Certificate) certificates[0]);

        // prevent replay attacks
        if (!Arrays.equals(attestation.getAttestationChallenge(), challenge)) {
            throw new GeneralSecurityException("challenge mismatch");
        }

        // version sanity checks
        if (attestation.getAttestationVersion() < 2) {
            throw new GeneralSecurityException("attestation version below 2");
        }
        if (attestation.getAttestationSecurityLevel() != Attestation.KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT) {
            throw new GeneralSecurityException("attestation security level is software");
        }
        if (attestation.getKeymasterVersion() < 3) {
            throw new GeneralSecurityException("keymaster version below 3");
        }
        if (attestation.getKeymasterSecurityLevel() != Attestation.KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT) {
            throw new GeneralSecurityException("keymaster security level is software");
        }

        // enforce communicating with the attestation app via OS level security
        final AuthorizationList softwareEnforced = attestation.getSoftwareEnforced();
        final AttestationApplicationId attestationApplicationId = softwareEnforced.getAttestationApplicationId();
        final List<AttestationPackageInfo> infos = attestationApplicationId.getAttestationPackageInfos();
        if (infos.size() != 1) {
            throw new GeneralSecurityException("wrong number of attestation packages");
        }
        final AttestationPackageInfo info = infos.get(0);
        if (!"co.copperhead.attestation".equals(info.getPackageName())) {
            throw new GeneralSecurityException("wrong attestation app package name");
        }
        if (info.getVersion() < 1) {
            throw new GeneralSecurityException("attestation app is too old");
        }
        // TODO: check attestation package signature once it uses a release signature

        final AuthorizationList teeEnforced = attestation.getTeeEnforced();

        // key sanity checks
        if (teeEnforced.getOrigin() != AuthorizationList.KM_ORIGIN_GENERATED) {
            throw new GeneralSecurityException("not a generated key");
        }
        if (!teeEnforced.isRollbackResistant()) {
            throw new GeneralSecurityException("expected rollback resistant key");
        }

        // verified boot security checks
        final RootOfTrust rootOfTrust = teeEnforced.getRootOfTrust();
        if (rootOfTrust == null) {
            throw new GeneralSecurityException("missing root of trust");
        }
        if (!rootOfTrust.isDeviceLocked()) {
            throw new GeneralSecurityException("device is not locked");
        }
        if (rootOfTrust.getVerifiedBootState() != RootOfTrust.KM_VERIFIED_BOOT_SELF_SIGNED) {
            throw new GeneralSecurityException("verified boot state is not self signed");
        }
        final String verifiedBootKey = BaseEncoding.base16().encode(rootOfTrust.getVerifiedBootKey());
        String device = null;
        if (verifiedBootKey.equals(COPPERHEADOS_FINGERPRINT_TAIMEN)) {
            device = "Pixel 2 XL";
        } else if (verifiedBootKey.equals(COPPERHEADOS_FINGERPRINT_WALLEYE)) {
            device = "Pixel 2";
        }
        if (device == null) {
            throw new GeneralSecurityException("invalid key fingerprint");
        }

        return new Verified(device, teeEnforced.getOsVersion(), teeEnforced.getOsPatchLevel());
    }

    private static void verifyCertificateSignatures(Certificate[] certChain)
            throws GeneralSecurityException {

        for (Certificate cert : certChain) {
            final byte[] derCert = cert.getEncoded();
            final String pemCertPre = Base64.encodeToString(derCert, Base64.NO_WRAP);
            Log.d("****", pemCertPre);
        }

        for (int i = 1; i < certChain.length; ++i) {
            PublicKey pubKey = certChain[i].getPublicKey();
            try {
                certChain[i - 1].verify(pubKey);
            } catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException
                    | NoSuchProviderException | SignatureException e) {
                throw new GeneralSecurityException("Failed to verify certificate "
                        + certChain[i - 1] + " with public key " + certChain[i].getPublicKey(), e);
            }
            if (i == certChain.length - 1) {
                // Last cert is self-signed.
                try {
                    certChain[i].verify(pubKey);
                } catch (CertificateException e) {
                    throw new GeneralSecurityException(
                            "Root cert " + certChain[i] + " is not correctly self-signed", e);
                }
            }
        }
    }

    private void testAttestation(final Context context) throws Exception {
        final String ecCurve = "secp256r1";
        final int keySize = 256;

        final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        final String freshKeystoreAlias = "fresh_attestation_key";
        keyStore.deleteEntry(freshKeystoreAlias);

        final String persistentKeystoreAlias = "persistent_attestation_key";
        final boolean hasPersistentKey = keyStore.containsAlias(persistentKeystoreAlias);

        // generate a new key for fresh attestation results unless the persistent key is not yet created
        final String attestationKeystoreAlias;
        if (hasPersistentKey) {
            attestationKeystoreAlias = "fresh_attestation_key";
        } else {
            attestationKeystoreAlias = persistentKeystoreAlias;
        }

        final SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(context);

        // this will be done by another device running the app to verify this one
        final byte[] challenge = getChallenge();
        if (!hasPersistentKey) {
            preferences.edit().putString(KEY_PERSISTENT_CHALLENGE, BaseEncoding.base64().encode(challenge)).apply();
        }

        Date startTime = new Date(new Date().getTime() - 1000);
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(attestationKeystoreAlias,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec(ecCurve))
                .setDigests(DIGEST_SHA256)
                .setAttestationChallenge(challenge)
                .setKeyValidityStart(startTime);
        if (hasPersistentKey) {
            builder.setKeyValidityEnd(new Date(startTime.getTime() + 60 * 1000));
        }
        generateKeyPair(KEY_ALGORITHM_EC, builder.build());

        byte[] signature = null;
        if (hasPersistentKey) {
            Signature sig = Signature.getInstance("SHA256WithECDSA");

            PrivateKey key = (PrivateKey) keyStore.getKey(persistentKeystoreAlias, null);
            sig.initSign(key);
            sig.update(challenge);
            signature = sig.sign();
        }

        // all of this verification will be done by a separate device

        final Certificate attestationCertificates[] = keyStore.getCertificateChain(attestationKeystoreAlias);
        final Verified verified = verifyAttestation(attestationCertificates, challenge);

        publishProgress("Successfully verified CopperheadOS attestation for ephemeral key.\n\n");
        publishProgress("Device: " + verified.device + "\n");

        final String osVersion = String.format("%06d", verified.osVersion);
        publishProgress("OS version: " +
                Integer.parseInt(osVersion.substring(0, 2)) + "." +
                Integer.parseInt(osVersion.substring(2, 4)) + "." +
                Integer.parseInt(osVersion.substring(4, 6)) + "\n");

        final String osPatchLevel = Integer.toString(verified.osPatchLevel);
        publishProgress("OS patch level: " + osPatchLevel.toString().substring(0, 4) + "-" + osPatchLevel.substring(4, 6) + "\n");

        if (hasPersistentKey) {
            final Certificate persistentCertificates[] = keyStore.getCertificateChain(persistentKeystoreAlias);
            verifyAttestation(persistentCertificates, BaseEncoding.base64().decode(preferences.getString(KEY_PERSISTENT_CHALLENGE, null)));

            publishProgress("\nSuccessfully verified CopperheadOS attestation for persistent key.\n");

            if (attestationCertificates.length != persistentCertificates.length) {
                throw new GeneralSecurityException("certificate chain mismatch");
            }
            for (int i = 1; i < attestationCertificates.length; i++) {
                X509Certificate a = (X509Certificate) attestationCertificates[i];
                X509Certificate b = (X509Certificate) persistentCertificates[i];
                if (!Arrays.equals(a.getEncoded(), b.getEncoded())) {
                    throw new GeneralSecurityException("certificate chain mismatch");
                }
            }
            publishProgress("\nEphemeral key certificate chain matches persistent key.\n");

            if (!verified.device.equals(preferences.getString(KEY_PINNED_DEVICE, null))) {
                throw new GeneralSecurityException("pinned device mismatch");
            }
            publishProgress("\nPinned device variant matches verified device variant.\n");

            if (verified.osVersion < preferences.getInt(KEY_PINNED_OS_VERSION, Integer.MAX_VALUE)) {
                throw new GeneralSecurityException("OS version downgrade detected");
            }
            if (verified.osPatchLevel < preferences.getInt(KEY_PINNED_OS_PATCH_LEVEL, Integer.MAX_VALUE)) {
                throw new GeneralSecurityException("OS patch level downgrade detected");
            }
            publishProgress("\nNo downgrade detected from pinned OS version and OS patch level.\n");

            if (attestationCertificates.length != preferences.getInt(KEY_PINNED_CERTIFICATE_LENGTH, 0)) {
                throw new GeneralSecurityException("certificate chain mismatch");
            }
            for (int i = 1; i < attestationCertificates.length; i++) {
                final X509Certificate a = (X509Certificate) attestationCertificates[i];
                final byte[] b = BaseEncoding.base64().decode(preferences.getString(KEY_PINNED_CERTIFICATE + "_" + i, null));
                if (!Arrays.equals(a.getEncoded(), b)) {
                    throw new GeneralSecurityException("certificate chain mismatch");
                }
            }
            publishProgress("\nCertificate chain matches pinned certificate chain.\n");

            final byte[] persistentCertificateEncoded = BaseEncoding.base64().decode(preferences.getString(KEY_PINNED_CERTIFICATE + "_0", null));
            X509Certificate persistentCertificate = (X509Certificate) CertificateFactory
                    .getInstance("X.509").generateCertificate(
                            new ByteArrayInputStream(
                                    persistentCertificateEncoded));
            PublicKey persistentPublicKey = persistentCertificate.getPublicKey();
            final Signature sig = Signature.getInstance("SHA256WithECDSA");
            sig.initVerify(persistentPublicKey);
            sig.update(challenge);
            if (!sig.verify(signature)) {
                throw new GeneralSecurityException("signature verification failed");
            }

            publishProgress("\nSuccessfully verified signature.");
        } else {
            final SharedPreferences.Editor editor = preferences.edit();

            editor.putString(KEY_PINNED_DEVICE, verified.device);

            editor.putInt(KEY_PINNED_CERTIFICATE_LENGTH, attestationCertificates.length);
            for (int i = 0; i < attestationCertificates.length; i++) {
                final X509Certificate cert = (X509Certificate) attestationCertificates[i];
                final String encoded = BaseEncoding.base64().encode(cert.getEncoded());
                editor.putString(KEY_PINNED_CERTIFICATE + "_" + i, encoded);
            }

            editor.apply();
        }

        preferences.edit()
                .putInt(KEY_PINNED_OS_VERSION, verified.osVersion)
                .putInt(KEY_PINNED_OS_PATCH_LEVEL, verified.osPatchLevel)
                .apply();
    }

    private static void generateKeyPair(String algorithm, KeyGenParameterSpec spec)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm,
                "AndroidKeyStore");
        keyPairGenerator.initialize(spec);
        keyPairGenerator.generateKeyPair();
    }
}
