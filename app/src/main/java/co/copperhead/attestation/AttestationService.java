package co.copperhead.attestation;

import co.copperhead.attestation.attestation.AuthorizationList;
import co.copperhead.attestation.attestation.Attestation;
import co.copperhead.attestation.attestation.AttestationApplicationId;
import co.copperhead.attestation.attestation.AttestationPackageInfo;
import co.copperhead.attestation.attestation.RootOfTrust;

import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import com.google.common.io.BaseEncoding;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.ByteBuffer;
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
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;

import java.security.cert.X509Certificate;

import static android.security.keystore.KeyProperties.DIGEST_SHA256;
import static android.security.keystore.KeyProperties.KEY_ALGORITHM_EC;

class AttestationService extends AsyncTask<Object, String, byte[]> {
    private static final String TAG = "AttestationService";

    private static final String KEY_PINNED_CERTIFICATE = "pinned_certificate";
    private static final String KEY_PINNED_CERTIFICATE_LENGTH = "pinned_certificate_length";
    private static final String KEY_PINNED_DEVICE = "pinned_device";
    private static final String KEY_PINNED_OS_VERSION = "pinned_os_version";
    private static final String KEY_PINNED_OS_PATCH_LEVEL = "pinned_os_patch_level";
    private static final String KEY_VERIFIED_TIME_FIRST = "verified_time_first";
    private static final String KEY_VERIFIED_TIME_LAST = "verified_time_last";

    private static final byte PROTOCOL_VERSION = 1;
    private static final int MAX_CERTIFICATE_LENGTH = 2000;
    // cat samples/taimen_attestation.der.x509 samples/taimen_intermediate.der.x509 | base64
    private static final byte[] DEFLATE_DICTIONARY = BaseEncoding.base64().decode(
            "MIICZjCCAg2gAwIBAgIBATAKBggqhkjOPQQDAjAbMRkwFwYDVQQFExBkNzc1MjM0ODY2ZjM3ZjUz" +
            "MCAXDTE4MDIwNTAxNDM1OVoYDzIxMDYwMjA3MDYyODE1WjAfMR0wGwYDVQQDDBRBbmRyb2lkIEtl" +
            "eXN0b3JlIEtleTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABODxAGPDQUKeGN90LJ30XS5voSvK" +
            "VvEj2a0UP7R6fOy+pob45fFAH1qvqqLv9J6Ajb7PZX7HTpanJ7uaIQ5wpRmjggE6MIIBNjAOBgNV" +
            "HQ8BAf8EBAMCB4AwggEiBgorBgEEAdZ5AgERBIIBEjCCAQ4CAQIKAQECAQMKAQEEIHpMSeMQFv3g" +
            "4qCffZTszv/WNaIc3ePgFDtbvAM/uwLvBAAwZr+DEAgCBgFhY6JZLr+FPQgCBgFhY6Meu7+FRUoE" +
            "SDBGMSAwHgQZY28uY29wcGVyaGVhZC5hdHRlc3RhdGlvbgIBATEiBCAW9DOe5NbEQZ3vCP9JSfcq" +
            "G5CR7Ymx/pRH8xqOO8y8bzB0oQgxBgIBAgIBA6IDAgEDowQCAgEApQUxAwIBBKoDAgEBv4N3AgUA" +
            "v4U+AwIBAL+FPwIFAL+FQCowKAQgFxYW6u8mAJ/EbcbYnz0kIX6SbIGmfOZdLjqdwnBAx6sBAf8K" +
            "AQC/hUEFAgMBOOS/hUIFAgMDFEkwCgYIKoZIzj0EAwIDRwAwRAIgRQm5K1AAPmPc5lcJm3sICuav" +
            "Zfaf3RBuEZHHpmc17YoCIAroE4eLaP5edIVWDGYCR5dTgEY3TOkACdQsQvfZCOKaMIICKTCCAa+g" +
            "AwIBAgIJaDkSRnQoRzlhMAoGCCqGSM49BAMCMBsxGTAXBgNVBAUTEDg3ZjQ1MTQ0NzViYTBhMmIw" +
            "HhcNMTYwNTI2MTcwNzMzWhcNMjYwNTI0MTcwNzMzWjAbMRkwFwYDVQQFExBkNzc1MjM0ODY2ZjM3" +
            "ZjUzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqrXOysRNrb+GjpMdrmsXrqq+jyLaahkcgCo6" +
            "rAROyYWOKaERvaFowtGsxkSfMSbqopj3qp//JBOW5iRrHRcp4KOB2zCB2DAdBgNVHQ4EFgQUL78c" +
            "0llO0rDTlgtwnhdE3BoQUEswHwYDVR0jBBgwFoAUMEQj5aL2BuFQq3dfFha7kcxjxlkwDAYDVR0T" +
            "AQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwJAYDVR0eBB0wG6AZMBeCFWludmFsaWQ7ZW1haWw6aW52" +
            "YWxpZDBSBgNVHR8ESzBJMEegRaBDhkFodHRwczovL2FuZHJvaWQuZ29vZ2xlYXBpcy5jb20vYXR0" +
            "ZXN0YXRpb24vY3JsLzY4MzkxMjQ2NzQyODQ3Mzk2MTAKBggqhkjOPQQDAgNoADBlAjA9rA4BW4Nt" +
            "HoD3nXysHziKlLoAhCup8V4dNmWu6htIt43I3ANmVm7CzetNqgEjNPACMQCBuDKKwLOHBA9a/dHb" +
            "9y8ApGZ+AU6StdxH/rHPYRFq84/5WOmUV7vPeFuRoMPe080=");

    private static final int CHALLENGE_LENGTH = 32;
    private static final String EC_CURVE = "secp256r1";
    private static final String SIGNATURE_ALGORITHM = "SHA256WithECDSA";
    private static final String KEY_DIGEST = DIGEST_SHA256;
    private static final HashFunction FINGERPRINT_HASH_FUNCTION = Hashing.sha256();
    private static final int FINGERPRINT_LENGTH = FINGERPRINT_HASH_FUNCTION.bits() / 8;

    private static final String ATTESTATION_APP_PACKAGE_NAME = "co.copperhead.attestation";
    private static final int ATTESTATION_APP_MINIMUM_VERSION = 2;
    private static final String ATTESTATION_APP_SIGNATURE_DIGEST =
            BuildConfig.DEBUG ?
                    "17727D8B61D55A864936B1A7B4A2554A15151F32EBCF44CDAA6E6C3258231890" :
                    "16F4339EE4D6C4419DEF08FF4949F72A1B9091ED89B1FE9447F31A8E3BCCBC6F";
    private static final int OS_VERSION_MINIMUM = 80100;
    private static final int OS_PATCH_LEVEL_MINIMUM = 201801;

    // Root for Google certified devices.
    private static final String GOOGLE_ROOT_CERTIFICATE =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIFYDCCA0igAwIBAgIJAOj6GWMU0voYMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV" +
            "BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTYwNTI2MTYyODUyWhcNMjYwNTI0MTYy" +
            "ODUyWjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B" +
            "AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS" +
            "Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7" +
            "tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj" +
            "nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq" +
            "C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ" +
            "oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O" +
            "JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg" +
            "sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi" +
            "igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M" +
            "RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E" +
            "aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um" +
            "AGMCAwEAAaOBpjCBozAdBgNVHQ4EFgQUNmHhAHyIBQlRi0RsR/8aTMnqTxIwHwYD" +
            "VR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwDwYDVR0TAQH/BAUwAwEB/zAO" +
            "BgNVHQ8BAf8EBAMCAYYwQAYDVR0fBDkwNzA1oDOgMYYvaHR0cHM6Ly9hbmRyb2lk" +
            "Lmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC8wDQYJKoZIhvcNAQELBQAD" +
            "ggIBACDIw41L3KlXG0aMiS//cqrG+EShHUGo8HNsw30W1kJtjn6UBwRM6jnmiwfB" +
            "Pb8VA91chb2vssAtX2zbTvqBJ9+LBPGCdw/E53Rbf86qhxKaiAHOjpvAy5Y3m00m" +
            "qC0w/Zwvju1twb4vhLaJ5NkUJYsUS7rmJKHHBnETLi8GFqiEsqTWpG/6ibYCv7rY" +
            "DBJDcR9W62BW9jfIoBQcxUCUJouMPH25lLNcDc1ssqvC2v7iUgI9LeoM1sNovqPm" +
            "QUiG9rHli1vXxzCyaMTjwftkJLkf6724DFhuKug2jITV0QkXvaJWF4nUaHOTNA4u" +
            "JU9WDvZLI1j83A+/xnAJUucIv/zGJ1AMH2boHqF8CY16LpsYgBt6tKxxWH00XcyD" +
            "CdW2KlBCeqbQPcsFmWyWugxdcekhYsAWyoSf818NUsZdBWBaR/OukXrNLfkQ79Iy" +
            "ZohZbvabO/X+MVT3rriAoKc8oE2Uws6DF+60PV7/WIPjNvXySdqspImSN78mflxD" +
            "qwLqRBYkA3I75qppLGG9rp7UCdRjxMl8ZDBld+7yvHVgt1cVzJx9xnyGCC23Uaic" +
            "MDSXYrB4I4WHXPGjxhZuCuPBLTdOLU8YRvMYdEvYebWHMpvwGCF6bAx3JBpIeOQ1" +
            "wDB5y0USicV3YgYGmi+NZfhA4URSh77Yd6uuJOJENRaNVTzk\n" +
            "-----END CERTIFICATE-----";

    // Intermediate for Pixel 2 and Pixel 2 XL devices.
    //
    // Google doesn't provide any kind of guarantee that this intermediate is
    // used on the Pixel 2 and Pixel 2 XL but it appears universal in practice.
    //
    // 'wahoo' is the shared codename for walleye (Pixel 2) and taimen (Pixel 2 XL)
    private static final String WAHOO_INTERMEDIATE_CERTIFICATE =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIDwzCCAaugAwIBAgIKA4gmZ2BliZaFdTANBgkqhkiG9w0BAQsFADAbMRkwFwYD" +
            "VQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTE2MDUyNjE3MDE1MVoXDTI2MDUyNDE3" +
            "MDE1MVowGzEZMBcGA1UEBRMQODdmNDUxNDQ3NWJhMGEyYjB2MBAGByqGSM49AgEG" +
            "BSuBBAAiA2IABGQ7VmgdJ/rEgs9sIE3rzvApXDUMAaqMMn8+1fRJrvQpZkJfOT2E" +
            "djtdrVaxDQRZxixqT5MlVqiSk8PRTqLx3+8OPLoicqMiOeGytH2sVQurvFynVeKq" +
            "SGKK1jx2/2fccqOBtjCBszAdBgNVHQ4EFgQUMEQj5aL2BuFQq3dfFha7kcxjxlkw" +
            "HwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwDwYDVR0TAQH/BAUwAwEB" +
            "/zAOBgNVHQ8BAf8EBAMCAYYwUAYDVR0fBEkwRzBFoEOgQYY/aHR0cHM6Ly9hbmRy" +
            "b2lkLmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC9FOEZBMTk2MzE0RDJG" +
            "QTE4MA0GCSqGSIb3DQEBCwUAA4ICAQBAOYqLNryTmbOlnrjnIvDoXxzaLOgCXu29" +
            "l7KpbFHacVLxgYuGRiIEQqzZBqUYSt9Pgx+P2KvoHtz99sEZr2xTe0Dw6CTHTAmx" +
            "WXUFdrlvEMm2GySfvJRfMNCuX1oIS/M5PfREY2YZHyLq/sn1sJr3FjbKMdUMBo5A" +
            "camcD3H8wl9O/6qfhX+57iXzoK6yMzJRG/Mlkm58/sFk0pjayUBchmUJL0FQ6IhK" +
            "Ygy8RKE2UDyXKOE7+ZMSMUUkAdzyn2PFv7TvQtDk0ge2mkVrNrfPSglMzBNvrSDH" +
            "PBmTktXzwseVagIRT5WI91OrUOYPFgostsfH42hs5wJtAFGPwDg/1mNa8UyH9k1b" +
            "MrRq3Srez1XG0Ju7SGN/uNX5dkcwvfAmadtmM7Pp+l2VHRYRR600jAcM2+7bl8eg" +
            "qfM/A7vyDLZqPIxDwkLXj2eN99nJZJVaGfB9dHyFOqBqBM6SdyV6MSIr3AHoo6u+" +
            "BWIX9+q8n1qg5I6JWeEe+K58SbRDVoNQgsKP9/iPruXMU5rm2ywPxICVGysl1GgA" +
            "P+FJ3X6oP0tXFWQlYoWdSloSVHNZQqj2ev/69sMnGsTeJw1V7I0gR+eZNEfxe+vZ" +
            "D4KP88KxuiPCe94rp+Aqs5/YwuCo6rQ+HGi5OZNBsQXYIufClSBje+OpjQb7HJgi" +
            "hJdzo2/IBw==\n" +
            "-----END CERTIFICATE-----";

    private static final String FINGERPRINT_COPPERHEADOS_TAIMEN =
            "815DCBA82BAC1B1758211FF53CAA0B6883CB6C901BE285E1B291C8BDAA12DF75";
    private static final String FINGERPRINT_COPPERHEADOS_WALLEYE =
            "36D067F8517A2284781B99A2984966BFF02D3F47310F831FCDCC4D792426B6DF";
    private static final String FINGERPRINT_STOCK_TAIMEN =
            "171616EAEF26009FC46DC6D89F3D24217E926C81A67CE65D2E3A9DC27040C7AB";
    private static final String FINGERPRINT_STOCK_WALLEYE =
            "1962B0538579FFCE9AC9F507C46AFE3B92055BAC7146462283C85C500BE78D82";

    private final AttestationActivity activity;
    private final TextView view;

    AttestationService(AttestationActivity activity, TextView view) {
        this.activity = activity;
        this.view = view;
    }

    @Override
    protected byte[] doInBackground(Object... params) {
        boolean verify = (Boolean) params[0];
        try {
            if (verify) {
                verifyAttestation(activity, (byte[]) params[1], (byte[]) params[2]);
                return null;
            } else {
                return generateAttestation((byte[]) params[1]);
            }
        } catch (Exception e) {
            final StringWriter s = new StringWriter();
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

    @Override
    protected void onPostExecute(final byte[] serialized) {
        if (serialized != null) {
            activity.continueAuditeeShowAttestation(serialized);
        }
    }

    static byte[] getChallenge() {
        final SecureRandom random = new SecureRandom();
        final byte[] challenge = new byte[CHALLENGE_LENGTH];
        random.nextBytes(challenge);
        return challenge;
    }

    private static String getFingerprint(final X509Certificate certificate)
            throws CertificateEncodingException {
        return FINGERPRINT_HASH_FUNCTION.hashBytes(certificate.getEncoded()).toString().toUpperCase();
    }

    private static byte[] getFingerprintBytes(final X509Certificate certificate)
            throws CertificateEncodingException {
        return FINGERPRINT_HASH_FUNCTION.hashBytes(certificate.getEncoded()).asBytes();
    }

    private static class Verified {
        final String device;
        final int osVersion;
        final int osPatchLevel;
        final boolean isStock;

        Verified(final String device, final int osVersion, final int osPatchLevel, final boolean isStock) {
            this.device = device;
            this.osVersion = osVersion;
            this.osPatchLevel = osPatchLevel;
            this.isStock = isStock;
        }
    }

    private static Verified verifyAttestation(final Certificate[] certificates, final byte[] challenge)
            throws GeneralSecurityException {

        verifyCertificateSignatures(certificates);

        // Pixel 2 (XL) is expected to use a 4 certificate chain (likely to always be the case)
        if (certificates.length != 4) {
            throw new GeneralSecurityException("certificate chain does not match expected length for a supported device");
        }

        // check that the root certificate is the Google key attestation root
        final X509Certificate secureRoot = (X509Certificate) CertificateFactory
                .getInstance("X.509").generateCertificate(
                        new ByteArrayInputStream(GOOGLE_ROOT_CERTIFICATE.getBytes()));
        final X509Certificate rootCert = (X509Certificate) certificates[certificates.length - 1];
        if (!Arrays.equals(secureRoot.getEncoded(), rootCert.getEncoded())) {
            throw new GeneralSecurityException("root certificate is not the Google key attestation root");
        }

        // check that 2nd last certificate is the expected intermediate (may prove to be too strict)
        final X509Certificate pixelIntermediate = (X509Certificate) CertificateFactory
                .getInstance("X.509").generateCertificate(
                        new ByteArrayInputStream(WAHOO_INTERMEDIATE_CERTIFICATE.getBytes()));
        final X509Certificate intermediateCert = (X509Certificate) certificates[certificates.length - 2];
        if (!Arrays.equals(pixelIntermediate.getEncoded(), intermediateCert.getEncoded())) {
            throw new GeneralSecurityException("2nd last certificate is not the Pixel 2 (XL) intermediate");
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
        if (!ATTESTATION_APP_PACKAGE_NAME.equals(info.getPackageName())) {
            throw new GeneralSecurityException("wrong attestation app package name");
        }
        if (info.getVersion() < ATTESTATION_APP_MINIMUM_VERSION) {
            throw new GeneralSecurityException("attestation app is too old");
        }
        final List<byte[]> signatureDigests = attestationApplicationId.getSignatureDigests();
        if (signatureDigests.size() != 1) {
            throw new GeneralSecurityException("wrong number of attestation app signature digests");
        }
        final String signatureDigest = BaseEncoding.base16().encode(signatureDigests.get(0));
        if (!ATTESTATION_APP_SIGNATURE_DIGEST.equals(signatureDigest)) {
            throw new GeneralSecurityException("wrong attestation app signature digest");
        }

        final AuthorizationList teeEnforced = attestation.getTeeEnforced();

        // key sanity checks
        if (teeEnforced.getOrigin() != AuthorizationList.KM_ORIGIN_GENERATED) {
            throw new GeneralSecurityException("not a generated key");
        }
        if (!teeEnforced.isRollbackResistant()) {
            throw new GeneralSecurityException("expected rollback resistant key");
        }

        // verified boot security checks
        final int osVersion = teeEnforced.getOsVersion();
        if (osVersion < OS_VERSION_MINIMUM) {
            throw new GeneralSecurityException("OS version too old");
        }
        final int osPatchLevel = teeEnforced.getOsPatchLevel();
        if (osPatchLevel < OS_PATCH_LEVEL_MINIMUM) {
            throw new GeneralSecurityException("OS patch level too old");
        }
        final RootOfTrust rootOfTrust = teeEnforced.getRootOfTrust();
        if (rootOfTrust == null) {
            throw new GeneralSecurityException("missing root of trust");
        }
        if (!rootOfTrust.isDeviceLocked()) {
            throw new GeneralSecurityException("device is not locked");
        }
        final int verifiedBootState = rootOfTrust.getVerifiedBootState();
        final String verifiedBootKey = BaseEncoding.base16().encode(rootOfTrust.getVerifiedBootKey());
        if (verifiedBootState == RootOfTrust.KM_VERIFIED_BOOT_SELF_SIGNED) {
            if (verifiedBootKey.equals(FINGERPRINT_COPPERHEADOS_TAIMEN)) {
                return new Verified("Pixel 2 XL", osVersion, osPatchLevel, false);
            } else if (verifiedBootKey.equals(FINGERPRINT_COPPERHEADOS_WALLEYE)) {
                return new Verified("Pixel 2", osVersion, osPatchLevel, false);
            }
            throw new GeneralSecurityException("invalid key fingerprint");
        } else if (verifiedBootState == RootOfTrust.KM_VERIFIED_BOOT_VERIFIED) {
            if (verifiedBootKey.equals(FINGERPRINT_STOCK_TAIMEN)) {
                return new Verified("Pixel 2 XL", osVersion, osPatchLevel, true);
            } else if (verifiedBootKey.equals(FINGERPRINT_STOCK_WALLEYE)) {
                return new Verified("Pixel 2", osVersion, osPatchLevel, true);
            }
            throw new GeneralSecurityException("invalid key fingerprint");
        }
        throw new GeneralSecurityException("verified boot state is not verified or self signed");
    }

    private static void verifyCertificateSignatures(Certificate[] certChain)
            throws GeneralSecurityException {

        for (final Certificate cert : certChain) {
            Log.d(TAG, Base64.encodeToString(cert.getEncoded(), Base64.NO_WRAP));
        }

        for (int i = 1; i < certChain.length; ++i) {
            final PublicKey pubKey = certChain[i].getPublicKey();
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

    private void publishVerifiedInformation(final Verified verified, final String fingerprint) {
        publishProgress("\nVerified device information:\n");
        publishProgress("\nDevice: " + verified.device + "\n");
        if (verified.isStock) {
            publishProgress("OS: Google Android (unmodified official release)\n");
        } else {
            publishProgress("OS: CopperheadOS (unmodified official release)\n");
        }

        final String osVersion = String.format("%06d", verified.osVersion);
        publishProgress("OS version: " +
                Integer.parseInt(osVersion.substring(0, 2)) + "." +
                Integer.parseInt(osVersion.substring(2, 4)) + "." +
                Integer.parseInt(osVersion.substring(4, 6)) + "\n");

        final String osPatchLevel = Integer.toString(verified.osPatchLevel);
        publishProgress("OS patch level: " +
                osPatchLevel.toString().substring(0, 4) + "-" +
                osPatchLevel.substring(4, 6) + "\n");

        publishProgress("Identity: " + fingerprint + "\n");
    }

    private void verify(final Context context, final String fingerprint, final byte[] challenge,
            final ByteBuffer signedMessage, final byte[] signature, final Certificate[] attestationCertificates,
            final boolean hasPersistentKey)
            throws GeneralSecurityException {

        final SharedPreferences preferences = context.getSharedPreferences(fingerprint, Context.MODE_PRIVATE);
        if (hasPersistentKey && !preferences.contains(KEY_PINNED_DEVICE)) {
            publishProgress("Device being verified is already paired with another verifier.\n");
            publishProgress("\nClear attestation app data on the device being verified to pair with this device.\n");
            return;
        }

        final Verified verified = verifyAttestation(attestationCertificates, challenge);

        publishProgress("Verified attestation with trusted root and trusted intermediate.\n");

        if (hasPersistentKey) {
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
            final X509Certificate persistentCertificate = (X509Certificate) CertificateFactory
                    .getInstance("X.509").generateCertificate(
                            new ByteArrayInputStream(
                                    persistentCertificateEncoded));
            if (!fingerprint.equals(getFingerprint(persistentCertificate))) {
                throw new GeneralSecurityException("received invalid fingerprint");
            }
            final Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
            sig.initVerify(persistentCertificate.getPublicKey());
            sig.update(signedMessage);
            if (!sig.verify(signature)) {
                throw new GeneralSecurityException("signature verification failed");
            }
            publishProgress("\nDevice identity confirmed with signed challenge.\n");

            publishVerifiedInformation(verified, fingerprint);
            publishProgress("First verified: " + new Date(preferences.getLong(KEY_VERIFIED_TIME_FIRST, 0)) + "\n");
            publishProgress("Last verified: " + new Date(preferences.getLong(KEY_VERIFIED_TIME_LAST, 0)) + "\n");

            preferences.edit()
                    .putInt(KEY_PINNED_OS_VERSION, verified.osVersion)
                    .putInt(KEY_PINNED_OS_PATCH_LEVEL, verified.osPatchLevel)
                    .putLong(KEY_VERIFIED_TIME_LAST, new Date().getTime())
                    .apply();
        } else {
            final String realFingerprint = getFingerprint((X509Certificate) attestationCertificates[0]);
            if (!fingerprint.equals(realFingerprint)) {
                throw new GeneralSecurityException("received invalid fingerprint");
            }
            publishVerifiedInformation(verified, fingerprint);

            final SharedPreferences.Editor editor = preferences.edit();

            editor.putInt(KEY_PINNED_CERTIFICATE_LENGTH, attestationCertificates.length);
            for (int i = 0; i < attestationCertificates.length; i++) {
                final X509Certificate cert = (X509Certificate) attestationCertificates[i];
                final String encoded = BaseEncoding.base64().encode(cert.getEncoded());
                editor.putString(KEY_PINNED_CERTIFICATE + "_" + i, encoded);
            }

            editor.putString(KEY_PINNED_DEVICE, verified.device);
            editor.putInt(KEY_PINNED_OS_VERSION, verified.osVersion);
            editor.putInt(KEY_PINNED_OS_PATCH_LEVEL, verified.osPatchLevel);

            final long now = new Date().getTime();
            editor.putLong(KEY_VERIFIED_TIME_FIRST, now);
            editor.putLong(KEY_VERIFIED_TIME_LAST, now);

            editor.apply();
        }
    }

    private byte[] generateAttestation(final byte[] challenge) throws Exception {
        final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        final String freshKeystoreAlias = "fresh_attestation_key";
        keyStore.deleteEntry(freshKeystoreAlias);

        final String persistentKeystoreAlias = "persistent_attestation_key";
        final boolean hasPersistentKey = keyStore.containsAlias(persistentKeystoreAlias);

        // generate a new key for fresh attestation results unless the persistent key is not yet created
        final String attestationKeystoreAlias;
        if (hasPersistentKey) {
            attestationKeystoreAlias = freshKeystoreAlias;
        } else {
            attestationKeystoreAlias = persistentKeystoreAlias;
        }

        final Date startTime = new Date(new Date().getTime() - 10 * 1000);
        final KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(attestationKeystoreAlias,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec(EC_CURVE))
                .setDigests(KEY_DIGEST)
                .setAttestationChallenge(challenge)
                .setKeyValidityStart(startTime);
        if (hasPersistentKey) {
            builder.setKeyValidityEnd(new Date(startTime.getTime() + 60 * 1000));
        }
        generateKeyPair(KEY_ALGORITHM_EC, builder.build());

        final byte[] fingerprint =
                getFingerprintBytes((X509Certificate) keyStore.getCertificate(persistentKeystoreAlias));

        final Certificate[] attestationCertificates = keyStore.getCertificateChain(attestationKeystoreAlias);

        // sanity check on the device being verified before sending it off to the verifying device
        verifyAttestation(attestationCertificates, challenge);

        final ByteBuffer serializer = ByteBuffer.allocate(3000);

        serializer.put(PROTOCOL_VERSION);
        final int certificateCount = attestationCertificates.length - 2;
        for (int i = 0; i < certificateCount; i++) {
            final X509Certificate certificate = (X509Certificate) attestationCertificates[i];
            final byte[] encoded = certificate.getEncoded();
            if (encoded.length > MAX_CERTIFICATE_LENGTH) {
                throw new GeneralSecurityException("certificate is too large");
            }

            final ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
            final Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
            deflater.setDictionary(DEFLATE_DICTIONARY);
            final DeflaterOutputStream deflaterStream = new DeflaterOutputStream(byteStream, deflater);
            deflaterStream.write(encoded);
            deflaterStream.finish();
            final byte[] compressed = byteStream.toByteArray();

            Log.d(TAG, "encoded length: " + encoded.length + ", compressed length: " + compressed.length);

            if (compressed.length > Short.MAX_VALUE) {
                throw new RuntimeException("compressed encoded certificate too long");
            }
            serializer.putShort((short)compressed.length);
            serializer.put(compressed);
        }

        if (fingerprint.length != FINGERPRINT_LENGTH) {
            throw new RuntimeException("fingerprint length mismatch");
        }
        serializer.put(fingerprint);
        serializer.put(hasPersistentKey ? (byte)1 : (byte)0);

        final ByteBuffer message = serializer.duplicate();
        message.flip();

        final Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
        sig.initSign((PrivateKey) keyStore.getKey(persistentKeystoreAlias, null));
        sig.update(message);
        final byte[] signature = sig.sign();

        serializer.put(signature);

        serializer.flip();
        final byte[] serialized = new byte[serializer.remaining()];
        serializer.get(serialized);

        return serialized;
    }

    // Attestation message:
    //
    // PROTOCOL_VERSION == 1 implies certificateCount == 2
    //
    // Compression is done with raw DEFLATE (no zlib wrapper).
    //
    // signed message {
    // byte version = PROTOCOL_VERSION
    // [short compressedCertificateLength, byte[] compressedCertificate] x certificateCount
    // byte[] fingerprint (length: FINGERPRINT_LENGTH)
    // byte hasPersistentKey
    // }
    // byte[] signature (rest of message)

    private void verifyAttestation(final Context context, final byte[] attestationResult, final byte[] challenge) throws Exception {
        final ByteBuffer deserializer = ByteBuffer.wrap(attestationResult);
        final byte version = deserializer.get();
        if (version != PROTOCOL_VERSION) {
            throw new GeneralSecurityException("unsupported protocol version: " + version);
        }
        final int certificateCount = 2;
        final Certificate[] certificates = new Certificate[certificateCount + 2];
        for (int i = 0; i < certificateCount; i++) {
            final int compressedLength = deserializer.getShort();
            final byte[] compressed = new byte[compressedLength];
            deserializer.get(compressed);

            final byte[] encoded = new byte[MAX_CERTIFICATE_LENGTH];

            final Inflater inflater = new Inflater(true);
            inflater.setInput(compressed);
            inflater.setDictionary(DEFLATE_DICTIONARY);
            final int encodedLength = inflater.inflate(encoded);
            if (!inflater.finished()) {
                throw new GeneralSecurityException("certificate is too large");
            }
            inflater.end();

            Log.d(TAG, "encoded length: " + encodedLength + ", compressed length: " + compressed.length);

            certificates[i] = CertificateFactory
                    .getInstance("X.509").generateCertificate(
                            new ByteArrayInputStream(encoded, 0, encodedLength));
        }
        final byte[] fingerprint = new byte[FINGERPRINT_LENGTH];
        deserializer.get(fingerprint);
        final byte hasPersistentKeyByte = deserializer.get();
        if (hasPersistentKeyByte != 0 && hasPersistentKeyByte != 1) {
            throw new GeneralSecurityException("invalid attestation");
        }
        final boolean hasPersistentKey = hasPersistentKeyByte == 1;
        final int signatureLength = deserializer.remaining();
        final byte[] signature = new byte[signatureLength];
        deserializer.get(signature);

        certificates[certificates.length - 2] = CertificateFactory
                .getInstance("X.509").generateCertificate(
                        new ByteArrayInputStream(WAHOO_INTERMEDIATE_CERTIFICATE.getBytes()));
        certificates[certificates.length - 1] = CertificateFactory
                .getInstance("X.509").generateCertificate(
                        new ByteArrayInputStream(GOOGLE_ROOT_CERTIFICATE.getBytes()));

        deserializer.rewind();
        deserializer.limit(deserializer.capacity() - signature.length);

        final String fingerprintHex = BaseEncoding.base16().encode(fingerprint);
        verify(context, fingerprintHex, challenge, deserializer.asReadOnlyBuffer(), signature, certificates, hasPersistentKey);
    }

    private static void generateKeyPair(final String algorithm, final KeyGenParameterSpec spec)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm,
                "AndroidKeyStore");
        keyPairGenerator.initialize(spec);
        keyPairGenerator.generateKeyPair();
    }
}
