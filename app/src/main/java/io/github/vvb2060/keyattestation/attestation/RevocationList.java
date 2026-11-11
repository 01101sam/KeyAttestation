package io.github.vvb2060.keyattestation.attestation;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import io.github.vvb2060.keyattestation.AppApplication;
import io.github.vvb2060.keyattestation.R;

public record RevocationList(String status, String reason) {
    private static final String DEFAULT_STATUS_URL = "https://android.googleapis.com/attestation/status";
    // Last-Modified of the embedded res/raw/status.json: Tue, 10 Nov 2026 02:38:00 GMT.
    // Update it together with the file.
    private static final long EMBEDDED_LAST_MODIFIED = 1794278280000L;
    private static final String CACHE_FILE = "revocation_status.json";
    private static final String PREFS_NAME = "revocation_list";
    private static final String KEY_LAST_MODIFIED = "last_modified";
    private static final String KEY_LAST_CHECKED = "last_checked";
    private static final String KEY_URL = "url";
    private static final int TIMEOUT_MS = 15000;

    /**
     * @param lastModified server Last-Modified time of this list, in milliseconds
     * @param downloaded   whether the list was downloaded, rather than embedded in the APK
     */
    public record Info(int entries, long lastModified, boolean downloaded,
                       long lastChecked, String url) {
    }

    private record Source(JSONObject entries, long lastModified, boolean downloaded) {
    }

    private static volatile Source source;

    private static String toString(InputStream input) throws IOException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        } else {
            var output = new ByteArrayOutputStream(8192);
            var buffer = new byte[8192];
            for (int length; (length = input.read(buffer)) != -1; ) {
                output.write(buffer, 0, length);
            }
            return output.toString("UTF-8");
        }
    }

    private static JSONObject parseStatus(String json) throws IOException {
        try {
            return new JSONObject(json).getJSONObject("entries");
        } catch (JSONException e) {
            throw new IOException(e);
        }
    }

    private static SharedPreferences prefs() {
        return AppApplication.app.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    private static File cacheFile() {
        return new File(AppApplication.app.getFilesDir(), CACHE_FILE);
    }

    private static String getStatusUrl() {
        var resName = "android:string/vendor_required_attestation_revocation_list_url";
        var res = AppApplication.app.getResources();
        // noinspection DiscouragedApi
        var id = res.getIdentifier(resName, null, null);
        if (id != 0) {
            var url = res.getString(id);
            if (!DEFAULT_STATUS_URL.equals(url) && url.toLowerCase(Locale.ROOT).startsWith("https")) {
                Log.i(AppApplication.TAG, "vendor revocation list url: " + url);
                return url;
            }
        }
        return DEFAULT_STATUS_URL;
    }

    private static Source getSource() {
        var current = source;
        if (current != null) return current;
        synchronized (RevocationList.class) {
            if (source == null) source = loadSource();
            return source;
        }
    }

    private static Source loadSource() {
        // A downloaded Google list is only used while it is newer than the one shipped in the
        // APK. A list from a vendor-specific URL always wins, the embedded one is Google's.
        var prefs = prefs();
        long cachedLastModified = prefs.getLong(KEY_LAST_MODIFIED, 0);
        var url = getStatusUrl();
        var file = cacheFile();
        boolean usable = url.equals(prefs.getString(KEY_URL, DEFAULT_STATUS_URL))
                && (!DEFAULT_STATUS_URL.equals(url) || cachedLastModified > EMBEDDED_LAST_MODIFIED);
        if (usable && cachedLastModified > 0 && file.isFile()) {
            try (var input = new FileInputStream(file)) {
                return new Source(parseStatus(toString(input)), cachedLastModified, true);
            } catch (IOException e) {
                Log.w(AppApplication.TAG, "Failed to load downloaded revocation list", e);
            }
        }
        try (var input = AppApplication.app.getResources().openRawResource(R.raw.status)) {
            return new Source(parseStatus(toString(input)), EMBEDDED_LAST_MODIFIED, false);
        } catch (IOException e) {
            throw new RuntimeException("Failed to parse certificate revocation status", e);
        }
    }

    /**
     * Downloads the latest revocation list. Must not be called on the main thread.
     *
     * @return true if a newer list was installed, false if the current one is up to date
     */
    public static boolean update() throws IOException {
        var url = getStatusUrl();
        var connection = (HttpURLConnection) new URL(url).openConnection();
        try {
            connection.setConnectTimeout(TIMEOUT_MS);
            connection.setReadTimeout(TIMEOUT_MS);
            connection.setUseCaches(false);
            connection.setRequestProperty("Cache-Control", "no-cache");
            int code = connection.getResponseCode();
            if (code != HttpURLConnection.HTTP_OK) {
                throw new IOException("HTTP " + code + " " + connection.getResponseMessage());
            }
            long lastModified = connection.getLastModified();
            String json;
            try (var input = connection.getInputStream()) {
                json = toString(input);
            }
            // Validate before replacing anything.
            var entries = parseStatus(json);
            prefs().edit().putLong(KEY_LAST_CHECKED, System.currentTimeMillis()).apply();
            if (lastModified == 0) lastModified = System.currentTimeMillis();

            var current = getSource();
            boolean notNewer = current.downloaded()
                    ? lastModified <= current.lastModified()
                    : DEFAULT_STATUS_URL.equals(url) && lastModified <= EMBEDDED_LAST_MODIFIED;
            if (notNewer) {
                return false;
            }

            var file = cacheFile();
            var tmp = new File(file.getPath() + ".tmp");
            try (var output = new FileOutputStream(tmp)) {
                output.write(json.getBytes(StandardCharsets.UTF_8));
                output.getFD().sync();
            }
            if (!tmp.renameTo(file)) {
                // noinspection ResultOfMethodCallIgnored
                tmp.delete();
                throw new IOException("Failed to save " + file);
            }
            prefs().edit()
                    .putLong(KEY_LAST_MODIFIED, lastModified)
                    .putString(KEY_URL, url)
                    .apply();
            source = new Source(entries, lastModified, true);
            return true;
        } finally {
            connection.disconnect();
        }
    }

    public static Info getInfo() {
        var current = getSource();
        return new Info(current.entries().length(), current.lastModified(), current.downloaded(),
                prefs().getLong(KEY_LAST_CHECKED, 0), getStatusUrl());
    }

    public static RevocationList get(BigInteger serialNumber) {
        String serialNumberString = serialNumber.toString(16).toLowerCase();
        JSONObject revocationStatus;
        try {
            revocationStatus = getSource().entries().getJSONObject(serialNumberString);
        } catch (JSONException e) {
            return null;
        }
        try {
            var status = revocationStatus.getString("status");
            var reason = revocationStatus.getString("reason");
            return new RevocationList(status, reason);
        } catch (JSONException e) {
            return new RevocationList("", "");
        }
    }

    @Override
    public String toString() {
        return "status is " + status + ", reason is " + reason;
    }
}
