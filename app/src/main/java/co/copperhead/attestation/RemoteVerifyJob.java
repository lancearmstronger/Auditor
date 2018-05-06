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

import co.copperhead.attestation.AttestationProtocol.AttestationResult;

public class RemoteVerifyJob extends JobService {
    private static final String TAG = "RemoteVerifyJob";
    private static final int JOB_ID = 0;
    static final String DOMAIN = "attestation.copperhead.co";
    private static final String CHALLENGE_URL = "https://" + DOMAIN + "/challenge";
    private static final String VERIFY_URL = "https://" + DOMAIN + "/verify";
    private static final int CONNECT_TIMEOUT = 60000;
    private static final int READ_TIMEOUT = 60000;
    private static final int MIN_INTERVAL = 60 * 60;
    private static final int MAX_INTERVAL = 7 * 24 * 60 * 60;
    private static final String STATE_PREFIX = "remote_";
    static final String KEY_USER_ID = "remote_user_id";
    static final String KEY_SUBSCRIBE_KEY = "remote_subscribe_key";

    private RemoteVerifyTask task;

    static boolean isScheduled(final Context context) {
        return context.getSystemService(JobScheduler.class).getPendingJob(JOB_ID) != null;
    }

    static class InvalidInterval extends Exception {
        InvalidInterval() {
            super("invalid interval");
        }
    }

    static boolean schedule(final Context context, final int interval) throws InvalidInterval {
        if (interval < MIN_INTERVAL || interval > MAX_INTERVAL) {
            throw new InvalidInterval();
        }
        final JobScheduler scheduler = context.getSystemService(JobScheduler.class);
        final JobInfo jobInfo = scheduler.getPendingJob(JOB_ID);
        final long intervalMillis = interval * 1000;
        final long flexMillis = intervalMillis / 10;
        if (jobInfo != null &&
                jobInfo.getIntervalMillis() == intervalMillis &&
                jobInfo.getFlexMillis() == flexMillis) {
            Log.d(TAG, "job already registered");
            return true;
        }
        final ComponentName serviceName = new ComponentName(context, RemoteVerifyJob.class);
        return scheduler.schedule(new JobInfo.Builder(JOB_ID, serviceName)
            .setPeriodic(intervalMillis, flexMillis)
            .setPersisted(true)
            .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
            .build()) == JobScheduler.RESULT_SUCCESS;
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
            HttpURLConnection connection = null;
            try {
                connection = (HttpURLConnection) new URL(CHALLENGE_URL).openConnection();
                connection.setConnectTimeout(CONNECT_TIMEOUT);
                connection.setReadTimeout(READ_TIMEOUT);
                connection.setRequestMethod("POST");

                final DataInputStream input = new DataInputStream(connection.getInputStream());
                final byte[] challengeMessage = new byte[AttestationProtocol.CHALLENGE_MESSAGE_LENGTH];
                input.readFully(challengeMessage);
                input.close();

                Log.d(TAG, "received random challenge: " + Utils.logFormatBytes(challengeMessage));

                final SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(RemoteVerifyJob.this);
                final long userId = preferences.getLong(KEY_USER_ID, -1);
                if (userId == -1) {
                    throw new IOException("missing userId");
                }
                final String subscribeKey = preferences.getString(KEY_SUBSCRIBE_KEY, null);
                if (subscribeKey == null) {
                    throw new IOException("missing subscribeKey");
                }

                final AttestationResult result = AttestationProtocol.generateSerialized(
                        RemoteVerifyJob.this, challengeMessage, Long.toString(userId), STATE_PREFIX);

                connection = (HttpURLConnection) new URL(VERIFY_URL).openConnection();
                connection.setConnectTimeout(CONNECT_TIMEOUT);
                connection.setReadTimeout(READ_TIMEOUT);
                connection.setDoOutput(true);
                final String extra = result.pairing ? " " + subscribeKey : "";
                connection.setRequestProperty("Authorization", "Auditor " + userId + extra);

                final OutputStream output = connection.getOutputStream();
                output.write(result.serialized);
                output.close();

                final int responseCode = connection.getResponseCode();
                if (responseCode == 200) {
                    try (final InputStream postResponse = connection.getInputStream()) {
                        final BufferedReader postReader = new BufferedReader(new InputStreamReader(postResponse));
                        final String[] tokens = postReader.readLine().split(" ");
                        if (tokens.length < 2) {
                            throw new GeneralSecurityException("missing fields");
                        }
                        preferences.edit().putString(KEY_SUBSCRIBE_KEY, tokens[0]).apply();
                        schedule(RemoteVerifyJob.this, Integer.parseInt(tokens[1]));
                    }
                } else {
                    if (result.pairing) {
                        AttestationProtocol.clearAuditee(STATE_PREFIX, Long.toString(userId));
                    }
                    throw new IOException("response code: " + responseCode);
                }
            } catch (final GeneralSecurityException | IOException | InvalidInterval |
                    NumberFormatException e) {
                Log.e(TAG, "remote verify failure", e);
                return true;
            } finally {
                if (connection != null) {
                    connection.disconnect();
                }
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
