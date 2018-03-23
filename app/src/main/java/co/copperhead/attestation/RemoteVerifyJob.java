package co.copperhead.attestation;

import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.preference.PreferenceManager;
import android.util.Log;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import co.copperhead.attestation.AttestationProtocol.AttestationResult;

public class RemoteVerifyJob extends JobService {
    private static final String TAG = "RemoteVerifyJob";
    private static final int JOB_ID = 0;
    private static final String VERIFY_URL = "https://attestation.copperhead.co/verify";
    private static final int CONNECT_TIMEOUT = 60000;
    private static final int READ_TIMEOUT = 60000;
    private static final int VERIFY_INTERVAL = 60 * 60 * 24;
    private static final String STATE_PREFIX = "remote_";
    static final String KEY_REMOTE_ACCOUNT = "remote_account";

    private RemoteVerifyTask task;

    static boolean isScheduled(final Context context) {
        return context.getSystemService(JobScheduler.class).getPendingJob(JOB_ID) != null;
    }

    static boolean schedule(final Context context, final int interval) {
        final JobScheduler scheduler = context.getSystemService(JobScheduler.class);
        final JobInfo jobInfo = scheduler.getPendingJob(JOB_ID);
        if (jobInfo != null && jobInfo.getIntervalMillis() == interval * 1000) {
            Log.d(TAG, "job already registered");
            return true;
        }
        final ComponentName serviceName = new ComponentName(context, RemoteVerifyJob.class);
        return scheduler.schedule(new JobInfo.Builder(JOB_ID, serviceName)
            .setPeriodic(interval * 1000)
            .setPersisted(true)
            .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
            .build()) == JobScheduler.RESULT_SUCCESS;
    }

    static boolean schedule(final Context context) {
        return schedule(context, VERIFY_INTERVAL);
    }

    static void cancel(final Context context) {
        context.getSystemService(JobScheduler.class).cancel(JOB_ID);
    }

    private class RemoteVerifyTask extends AsyncTask<Void, Void, Boolean> {
        final JobParameters params;

        RemoteVerifyTask(final JobParameters params) {
            this.params = params;
        }

        @Override
        protected void onPostExecute(final Boolean success) {
            jobFinished(params, success);
        }

        @Override
        protected Boolean doInBackground(final Void... params) {
            try {
                final HttpURLConnection getChallenge = (HttpURLConnection) new URL(VERIFY_URL).openConnection();
                getChallenge.setConnectTimeout(CONNECT_TIMEOUT);
                getChallenge.setReadTimeout(READ_TIMEOUT);

                final DataInputStream input = new DataInputStream(getChallenge.getInputStream());
                final byte[] challengeMessage = new byte[AttestationProtocol.CHALLENGE_MESSAGE_LENGTH];
                input.readFully(challengeMessage);
                input.close();

                Log.d(TAG, "received random challenge: " + Utils.logFormatBytes(challengeMessage));

                final AttestationResult result =
                        AttestationProtocol.generateSerialized(RemoteVerifyJob.this, challengeMessage, STATE_PREFIX);

                final SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(RemoteVerifyJob.this);
                final String account = preferences.getString(KEY_REMOTE_ACCOUNT, null);
                if (account == null) {
                    throw new IOException("missing account");
                }

                final HttpURLConnection postAttestation = (HttpURLConnection) new URL(VERIFY_URL + "/" + account).openConnection();
                postAttestation.setConnectTimeout(CONNECT_TIMEOUT);
                postAttestation.setReadTimeout(READ_TIMEOUT);
                postAttestation.setDoOutput(true);

                final OutputStream output = postAttestation.getOutputStream();
                output.write(result.serialized);
                output.close();

                final int responseCode = postAttestation.getResponseCode();
                if (responseCode == 200) {
                    try (final InputStream postResponse = postAttestation.getInputStream()) {
                        final BufferedReader postReader = new BufferedReader(new InputStreamReader(postResponse));
                        schedule(RemoteVerifyJob.this, Integer.parseInt(postReader.readLine()));
                    }
                    postAttestation.disconnect();
                } else {
                    postAttestation.disconnect();
                    if (result.pairing) {
                        final byte[] challengeIndex = Arrays.copyOfRange(challengeMessage, 1, 1 + AttestationProtocol.CHALLENGE_LENGTH);
                        AttestationProtocol.clearAuditee(STATE_PREFIX, challengeIndex);
                    }
                    throw new IOException("response code: " + responseCode);
                }
            } catch (final GeneralSecurityException | IOException | NumberFormatException e) {
                Log.e(TAG, "remote verify failure", e);
                return true;
            }
            return false;
        }
    }

    @Override
    public boolean onStartJob(final JobParameters params) {
        Log.d(TAG, "start job");
        task = new RemoteVerifyTask(params);
        task.execute();
        return true;
    }

    @Override
    public boolean onStopJob(final JobParameters params) {
        task.cancel(true);
        return true;
    }
}
