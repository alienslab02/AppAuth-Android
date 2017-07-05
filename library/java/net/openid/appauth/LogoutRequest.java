/*
 * Copyright 2015 The AppAuth for Android Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.openid.appauth;

import android.net.Uri;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Base64;

import org.json.JSONException;
import org.json.JSONObject;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import static net.openid.appauth.AdditionalParamsProcessor.builtInParams;
import static net.openid.appauth.AdditionalParamsProcessor.checkAdditionalParams;
import static net.openid.appauth.Preconditions.checkNotNull;

public class LogoutRequest {

    public static final String LOGOUT_URL = "https://www.google.com/accounts/Logout?continue=https://appengine.google.com/_ah/logout";
    private static final String PARAM_REDIRECT_URI = "continue";
    private static final String KEY_REDIRECT_URI = "redirectUri";
    private static final String KEY_ADDITIONAL_PARAMETERS = "additionalParameters";
    private static final int STATE_LENGTH = 16;

    private static final Set<String> BUILT_IN_PARAMS = builtInParams(PARAM_REDIRECT_URI);

    @NonNull
    public final Uri redirectUri;

    @NonNull
    public final Map<String, String> additionalParameters;

    /**
     * Creates instances of {@link LogoutRequest}.
     */
    public static final class Builder {


        // SuppressWarnings justification: static analysis incorrectly determines that this field
        // is not initialized, as it is indirectly initialized by setRedirectUri
        @NonNull
        @SuppressWarnings("NullableProblems")
        private Uri mRedirectUri;


        @NonNull
        private Map<String, String> mAdditionalParameters = new HashMap<>();

        /**
         * Creates a logout request builder with the specified mandatory properties.
         */
        public Builder(@NonNull Uri redirectUri) {
            setRedirectUri(redirectUri);
        }


        /**
         * Specifies the client's redirect URI. Cannot be null or empty.
         *
         * @see "The OAuth 2.0 Authorization Framework (RFC 6749), Section 3.1.2
         * <https://tools.ietf.org/html/rfc6749#section-3.1.2>"
         */
        @NonNull
        public Builder setRedirectUri(@NonNull Uri redirectUri) {
            mRedirectUri = checkNotNull(redirectUri, "redirect URI cannot be null or empty");
            return this;
        }

        /**
         * Specifies additional parameters. Replaces any previously provided set of parameters.
         * Parameter keys and values cannot be null or empty.
         *
         * @see "The OAuth 2.0 Authorization Framework (RFC 6749), Section 3.1
         * <https://tools.ietf.org/html/rfc6749#section-3.1>"
         */
        @NonNull
        public Builder setAdditionalParameters(@Nullable Map<String, String> additionalParameters) {
            mAdditionalParameters = checkAdditionalParams(additionalParameters, BUILT_IN_PARAMS);
            return this;
        }

        /**
         * Constructs the authorization request. At a minimum the following fields must have been
         * set:
         * <p>
         * - The client ID
         * - The expected response type
         * - The redirect URI
         * <p>
         * Failure to specify any of these parameters will result in a runtime exception.
         */
        @NonNull
        public LogoutRequest build() {
            return new LogoutRequest(
                mRedirectUri,
                Collections.unmodifiableMap(new HashMap<>(mAdditionalParameters)));
        }
    }

    private LogoutRequest(
        @NonNull Uri redirectUri,
        @NonNull Map<String, String> additionalParameters) {
        this.redirectUri = redirectUri;
        this.additionalParameters = additionalParameters;
    }

    /**
     * Produces a request URI, that can be used to dispath the authorization request.
     */
    @NonNull
    public Uri toUri() {
        Uri.Builder uriBuilder = Uri.parse(LOGOUT_URL).buildUpon()
            .appendQueryParameter(PARAM_REDIRECT_URI, redirectUri.toString());

        for (Entry<String, String> entry : additionalParameters.entrySet()) {
            uriBuilder.appendQueryParameter(entry.getKey(), entry.getValue());
        }

        return uriBuilder.build();
    }

    /**
     * Produces a JSON representation of the authorization request for persistent storage or local
     * transmission (e.g. between activities).
     */
    @NonNull
    public JSONObject jsonSerialize() {
        JSONObject json = new JSONObject();
        JsonUtil.put(json, KEY_REDIRECT_URI, redirectUri.toString());
        JsonUtil.put(json, KEY_ADDITIONAL_PARAMETERS,
            JsonUtil.mapToJsonObject(additionalParameters));
        return json;
    }

    /**
     * Produces a JSON string representation of the authorization request for persistent storage or
     * local transmission (e.g. between activities). This method is just a convenience wrapper
     * for {@link #jsonSerialize()}, converting the JSON object to its string form.
     */
    public String jsonSerializeString() {
        return jsonSerialize().toString();
    }

    /**
     * Reads an authorization request from a JSON string representation produced by
     * {@link #jsonSerialize()}.
     *
     * @throws JSONException if the provided JSON does not match the expected structure.
     */
    @NonNull
    public static LogoutRequest jsonDeserialize(@NonNull JSONObject json)
        throws JSONException {
        checkNotNull(json, "json cannot be null");
        LogoutRequest.Builder builder = new LogoutRequest.Builder(
            JsonUtil.getUri(json, KEY_REDIRECT_URI))
            .setAdditionalParameters(JsonUtil.getStringMap(json, KEY_ADDITIONAL_PARAMETERS));
        return builder.build();
    }

    /**
     * Reads an authorization request from a JSON string representation produced by
     * {@link #jsonSerializeString()}. This method is just a convenience wrapper for
     * {@link #jsonDeserialize(JSONObject)}, converting the JSON string to its JSON object form.
     *
     * @throws JSONException if the provided JSON does not match the expected structure.
     */
    @NonNull
    public static LogoutRequest jsonDeserialize(@NonNull String jsonStr)
        throws JSONException {
        checkNotNull(jsonStr, "json string cannot be null");
        return jsonDeserialize(new JSONObject(jsonStr));
    }

    private static String generateRandomState() {
        SecureRandom sr = new SecureRandom();
        byte[] random = new byte[STATE_LENGTH];
        sr.nextBytes(random);
        return Base64.encodeToString(random, Base64.NO_WRAP | Base64.NO_PADDING | Base64.URL_SAFE);
    }
}
