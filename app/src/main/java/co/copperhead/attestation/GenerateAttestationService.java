package co.copperhead.attestation;

import android.app.IntentService;
import android.app.PendingIntent;
import android.content.Intent;
import android.util.Log;

public class GenerateAttestationService extends IntentService {
    private static final String TAG = "GenerateAttestationService";

    static final String EXTRA_CHALLENGE_MESSAGE = "co.copperhead.attestation.CHALLENGE_MESSAGE";
    static final String EXTRA_PENDING_RESULT = "co.copperhead.attestation.PENDING_RESULT";

    static final String EXTRA_ATTESTATION = "co.copperhead.attestation.ATTESTATION";
    static final String EXTRA_ATTESTATION_ERROR = "co.copperhead.attestation.ATTESTATION_ERROR";

    static final int RESULT_CODE = 0;

    static final String ACTION_ATTESTATION = "co.copperhead.attestation.ACTION_ATTESTATION";

    public GenerateAttestationService() {
        super(TAG);
    }

    @Override
    protected void onHandleIntent(final Intent intent) {
        Log.d(TAG, "intent service started");

        final byte[] challengeMessage = intent.getByteArrayExtra(EXTRA_CHALLENGE_MESSAGE);
        if (challengeMessage == null) {
            throw new RuntimeException("no challenge message");
        }
        final PendingIntent pending = intent.getParcelableExtra(EXTRA_PENDING_RESULT);
        if (pending == null) {
            throw new RuntimeException("no pending intent");
        }

        final Intent resultIntent = new Intent(ACTION_ATTESTATION);

        try {
            final byte[] serialized = AttestationProtocol.generateSerialized(challengeMessage);
            resultIntent.putExtra(EXTRA_ATTESTATION, serialized);
        } catch (Exception e) {
            Log.e(TAG, "attestation generation error", e);
            resultIntent.putExtra(EXTRA_ATTESTATION_ERROR, e.getMessage());
        }

        try {
            pending.send(this, RESULT_CODE, resultIntent);
        } catch (PendingIntent.CanceledException e) {
            Log.e(TAG, "pending intent cancelled", e);
        }
    }
}
