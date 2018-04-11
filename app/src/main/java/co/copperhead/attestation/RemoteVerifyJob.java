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

import org.json.JSONObject;
import org.json.JSONException;

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
import java.util.stream.Collectors;

import co.copperhead.attestation.AttestationProtocol.AttestationResult;

public class RemoteVerifyJob extends JobService {
    private static final String TAG = "RemoteVerifyJob";
    private static final int JOB_ID = 0;
    static final String DOMAIN = "attestation.copperhead.co";
    private static final String CHALLENGE_URL = "https:/" + DOMAIN + "/challenge";
    private static final String VERIFY_URL = "https:/" + DOMAIN + "/verify";
    private static final int CONNECT_TIMEOUT = 60000;
    private static final int READ_TIMEOUT = 60000;
    private static final int MAX_INTERVAL = 60 * 60 * 24 * 7;
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
        if (interval > MAX_INTERVAL) {
            throw new InvalidInterval();
        }
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

                final AttestationResult result =
                        AttestationProtocol.generateSerialized(RemoteVerifyJob.this, challengeMessage, STATE_PREFIX);

                final SharedPreferences preferences = PreferenceManager.getDefaultSharedPreferences(RemoteVerifyJob.this);
                final long userId = preferences.getLong(KEY_USER_ID, -1);
                if (userId == -1) {
                    throw new IOException("missing userId");
                }
                final String subscribeKey = preferences.getString(KEY_SUBSCRIBE_KEY, null);
                if (subscribeKey == null) {
                    throw new IOException("missing subscribeKey");
                }

                final JSONObject token = new JSONObject();
                token.put("userId", userId);
                token.put("subscribeKey", subscribeKey);

                connection = (HttpURLConnection) new URL(VERIFY_URL).openConnection();
                connection.setConnectTimeout(CONNECT_TIMEOUT);
                connection.setReadTimeout(READ_TIMEOUT);
                connection.setDoOutput(true);
                connection.setRequestProperty("Authorization", "Bearer " + token);

                final OutputStream output = connection.getOutputStream();
                output.write(result.serialized);
                output.close();

                final int responseCode = connection.getResponseCode();
                if (responseCode == 200) {
                    try (final InputStream postResponse = connection.getInputStream()) {
                        final BufferedReader postReader = new BufferedReader(new InputStreamReader(postResponse));
                        final String json = postReader.lines().collect(Collectors.joining());
                        final JSONObject data = new JSONObject(json);

                        schedule(RemoteVerifyJob.this, data.getInt("verifyInterval"));
                        preferences.edit().putString(KEY_SUBSCRIBE_KEY,
                                data.getString("subscribeKey")).apply();
                    }
                } else {
                    if (result.pairing) {
                        final byte[] challengeIndex = Arrays.copyOfRange(challengeMessage, 1, 1 + AttestationProtocol.CHALLENGE_LENGTH);
                        AttestationProtocol.clearAuditee(STATE_PREFIX, challengeIndex);
                    }
                    throw new IOException("response code: " + responseCode);
                }
            } catch (final GeneralSecurityException | IOException | JSONException |
                    InvalidInterval | NumberFormatException e) {
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
