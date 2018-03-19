package co.copperhead.attestation;

import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;
import android.os.AsyncTask;
import android.util.Log;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;

public class RemoteVerifyJob extends JobService {
    private static final String TAG = "RemoteVerifyJob";
    private static final int JOB_ID = 0;
    private static final String VERIFY_URL = "https://attestation.copperhead.co/verify";
    private static final int CONNECT_TIMEOUT = 60000;
    private static final int READ_TIMEOUT = 60000;

    private RemoteVerifyTask task;

    static void schedule(final Context context) {
        final ComponentName serviceName = new ComponentName(context, RemoteVerifyJob.class);
        final JobScheduler scheduler = context.getSystemService(JobScheduler.class);
        final int result = scheduler.schedule(new JobInfo.Builder(JOB_ID, serviceName)
            .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
            .setPersisted(true)
            .build());
        if (result == JobScheduler.RESULT_FAILURE) {
            Log.d(TAG, "job schedule failed");
        }
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
                final HttpURLConnection connection = (HttpURLConnection) new URL(VERIFY_URL).openConnection();
                connection.setConnectTimeout(CONNECT_TIMEOUT);
                connection.setReadTimeout(READ_TIMEOUT);
                connection.setDoOutput(true);

                // TODO: fetch from server
                final byte[] challengeMessage = new byte[AttestationProtocol.CHALLENGE_MESSAGE_LENGTH];
                challengeMessage[0] = AttestationProtocol.PROTOCOL_VERSION;
                AttestationProtocol.generateSerialized(RemoteVerifyJob.this, challengeMessage, "remote_");

                final OutputStream output = connection.getOutputStream();
                output.close();

                final int responseCode = connection.getResponseCode();
                if (responseCode != 200) {
                    throw new IOException("response code: " + responseCode);
                }

                connection.disconnect();
            } catch (final GeneralSecurityException | IOException e) {
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
