package com.example.mo;


import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.util.Log;
import org.json.JSONException;
import org.json.JSONObject;
import java.util.HashMap;
import java.util.Map;
import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.JsonObjectRequest;
import com.android.volley.toolbox.StringRequest;
import com.android.volley.toolbox.Volley;


public class MiniOrangeSSO {
    private String clientId;
    private String clientSecret;
    private String baseUrl;
    private String redirectUri;
    private Context context;

    // Constructor
    public MiniOrangeSSO(Context context) {
        this.context = context;
    }

    // Setter methods
    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public void startAuthorization() {
        if (clientId == null || clientSecret == null || baseUrl == null || redirectUri == null) {
            Log.e("SSOManager", "SSO configuration is incomplete.");
            return;
        }
        String url = baseUrl + "/moas/idp/openidsso?client_id=" + clientId
                + "&redirect_uri=" + redirectUri + "&scope=email openid&response_type=code&state=abcd";
        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.setData(Uri.parse(url));
        context.startActivity(intent);
        Log.d("SSOManager", "OAuth initiated ...");
    }

    public void handleAuthorizationResponse(Uri uri, final ResponseCallback callback) {
        if (uri != null && uri.toString().startsWith(baseUrl + "/lander")) {
            String code = uri.getQueryParameter("code");
            requestToken(code, callback);
        }
    }

    private void requestToken(String code, final ResponseCallback callback) {
        if (clientId == null || clientSecret == null || baseUrl == null || redirectUri == null) {
            Log.e("SSOManager", "SSO configuration is incomplete.");
            callback.onError("Configuration is incomplete.");
            return;
        }

        String postUrl = baseUrl + "/moas/rest/oauth/token?" +
                "grant_type=authorization_code" +
                "&client_id=" + clientId +
                "&client_secret=" + clientSecret +
                "&redirect_uri=" + redirectUri +
                "&code=" + code;

        Log.d("SSOManager", "Making call on token endpoint with post URL: " + postUrl);

        RequestQueue requestQueue = Volley.newRequestQueue(context);

        JsonObjectRequest jsonObjectRequest = new JsonObjectRequest(Request.Method.POST, postUrl, null,
                new Response.Listener<JSONObject>() {
                    @Override
                    public void onResponse(JSONObject response) {
                        Log.d("SSOManager", "Response received ... : " + response.toString());
                        try {
                            String idToken = response.getString("id_token");
                            callback.onSuccess(idToken);
                        } catch (JSONException e) {
                            callback.onError("JSON parsing error: " + e.getMessage());
                        }
                    }
                }, new Response.ErrorListener() {
            @Override
            public void onErrorResponse(VolleyError error) {
                callback.onError("Request error: " + error.getMessage());
            }
        });

        requestQueue.add(jsonObjectRequest);
    }
    public void fetchUserInfo(String url, String token, final ResponseCallback callback) {
        RequestQueue requestQueue = Volley.newRequestQueue(context);

        StringRequest stringRequest = new StringRequest(Request.Method.GET, url,
                new Response.Listener<String>() {
                    @Override
                    public void onResponse(String response) {
                        callback.onSuccess(response);
                    }
                },
                new Response.ErrorListener() {
                    @Override
                    public void onErrorResponse(VolleyError error) {
                        callback.onError("Request error: " + error.getMessage());
                    }
                }) {
            @Override
            public Map<String, String> getHeaders() {
                Map<String, String> headers = new HashMap<>();
                headers.put("Authorization", "Bearer " + token);
                return headers;
            }
        };

        requestQueue.add(stringRequest);
    }
    public interface ResponseCallback {
        void onSuccess(String response);

        void onError(String error);
    }
}
