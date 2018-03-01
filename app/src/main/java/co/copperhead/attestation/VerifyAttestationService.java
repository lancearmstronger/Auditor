package co.copperhead.attestation;

import android.app.IntentService;
import android.app.PendingIntent;
import android.content.Intent;
import android.util.Log;

import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.security.GeneralSecurityException;
import java.util.zip.DataFormatException;

public class VerifyAttestationService extends IntentService {
    private static final String TAG = "VerifyAttestationService";

    static final String EXTRA_CHALLENGE_MESSAGE = "co.copperhead.attestation.CHALLENGE_MESSAGE";
    static final String EXTRA_SERIALIZED = "co.copperhead.attestation.SERIALIZED";
    static final String EXTRA_PENDING_RESULT = "co.copperhead.attestation.PENDING_RESULT";

    static final String EXTRA_STRONG = "co.copperhead.attestation.STRONG";
    static final String EXTRA_TEE_ENFORCED = "co.copperhead.attestation.TEE_ENFORCED";
    static final String EXTRA_OS_ENFORCED = "co.copperhead.attestation.OS_ENFORCED";
    static final String EXTRA_ERROR = "co.copperhead.attestation.ERROR";
    static final String EXTRA_CLEAR = "co.copperhead.attestation.CLEAR";

    static final int RESULT_CODE = 0;

    static final String ACTION_ATTESTATION = "co.copperhead.attestation.ACTION_ATTESTATION";

    public VerifyAttestationService() {
        super(TAG);
    }

    @Override
    protected void onHandleIntent(final Intent intent) {
        Log.d(TAG, "intent service started");

        if (intent.getBooleanExtra(EXTRA_CLEAR, false)) {
            AttestationProtocol.clearAuditor(this);
            return;
        }

        final byte[] challengeMessage = intent.getByteArrayExtra(EXTRA_CHALLENGE_MESSAGE);
        if (challengeMessage == null) {
            throw new RuntimeException("no challenge message");
        }
        final byte[] serialized = intent.getByteArrayExtra(EXTRA_SERIALIZED);
        if (serialized == null) {
            throw new RuntimeException("no serialized attestation");
        }
        final PendingIntent pending = intent.getParcelableExtra(EXTRA_PENDING_RESULT);
        if (pending == null) {
            throw new RuntimeException("no pending intent");
        }

        final Intent resultIntent = new Intent(ACTION_ATTESTATION);

        try {
            final AttestationProtocol.VerificationResult result = AttestationProtocol.verifySerialized(this, serialized, challengeMessage);
            resultIntent.putExtra(EXTRA_STRONG, result.strong);
            resultIntent.putExtra(EXTRA_TEE_ENFORCED, result.teeEnforced);
            resultIntent.putExtra(EXTRA_OS_ENFORCED, result.osEnforced);
        } catch (final DataFormatException | GeneralSecurityException | IOException e) {
            Log.e(TAG, "attestation generation error", e);
            resultIntent.putExtra(EXTRA_ERROR, e.getMessage());
        } catch (final BufferUnderflowException e) {
            Log.e(TAG, "attestation generation error", e);
            resultIntent.putExtra(EXTRA_ERROR, "Invalid attestation format");
        }

        try {
            pending.send(this, RESULT_CODE, resultIntent);
        } catch (PendingIntent.CanceledException e) {
            Log.e(TAG, "pending intent cancelled", e);
        }
    }
}
