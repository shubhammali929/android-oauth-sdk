package com.example.oauthfinal;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.android.volley.AuthFailureError;
import com.android.volley.NetworkResponse;
import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.JsonObjectRequest;
import com.android.volley.toolbox.StringRequest;
import com.android.volley.toolbox.Volley;
import com.example.mo.MiniOrangeSSO;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;


public class MainActivity extends AppCompatActivity {

    private void writeLogs() {
        try {
            // Get the current date
            SimpleDateFormat dateFormat = new SimpleDateFormat("dd-MM-yy", Locale.getDefault());
            String currentDate = dateFormat.format(new Date());
            // Create a log file with the name in "dd-MM-yy.txt" format
            File logFile = new File(getExternalFilesDir(null), currentDate + ".txt");
            // if log files doesn't exist then create new
            if (!logFile.exists()) {
                logFile.createNewFile();
            }
            // Redirect logcat output for the specific tag "myapp" to the file
            Process process = Runtime.getRuntime().exec("logcat -s myapp:V -f " + logFile.getAbsolutePath());
        } catch (IOException e) {
            Log.e("MainActivity", "Error redirecting Logcat to file", e);
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });
        
        //---------------START---------------------------------
        writeLogs();
        // ```````````````````Check if SharedPreferences has data if yes redirect user to 2nd activity``````````````````````````````
        SharedPreferences shrd = getSharedPreferences("userSession", MODE_PRIVATE);
        String firstName = shrd.getString("FirstName", null);
        if (firstName != null) {
            // If SharedPreferences has data, redirect to MainActivity2
            Log.d("myapp", "User sesson retrived ..");
            Intent intent = new Intent(MainActivity.this, MainActivity2.class);
            startActivity(intent);
            finish(); // Close the current activity
            return; // Prevent further execution
        }
        //``````````````````````````````````````````redirected user to 2nd activity`````````````````````````````````````````

        //getting data from url .../lander/data.......
        Uri uri = getIntent().getData();
        if (uri != null && uri.toString().startsWith("https://www.myapplication.com/lander")) {

            String code = uri.getQueryParameter("code");
            String state = uri.getQueryParameter("state");
            Log.d("myapp", "Auth code received : "+code);
            Log.d("myapp","Calling reqForToken function...");
            reqForToken(code);
        }

        EditText emailEditText = findViewById(R.id.editTextText5);
        EditText passwordEditText = findViewById(R.id.editTextTextPassword2);
        Button loginButtonPassswordGrant = findViewById(R.id.button2);
        Button OAuthBtn = findViewById(R.id.oauth);

        // Set up button click listener for Authorization Grant
        OAuthBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                String url = "https://testshubham.miniorange.in/moas/idp/openidsso?client_id=VOPiLgXkIeH2gHc&redirect_uri=https://www.myapplication.com/v1/callback&scope=email openid&response_type=code&state=abcd";
                Intent intent = new Intent(Intent.ACTION_VIEW);
                intent.setData(Uri.parse(url));
                startActivity(intent);
                Log.d("myapp", "OAuth initiated ...");
            }
        });

        // Set up button click listener for password grant
        loginButtonPassswordGrant.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // Fetch email and password from activity_main.xml
                String email = emailEditText.getText().toString().trim();
                String password = passwordEditText.getText().toString().trim();

                // Validate input check if not empty
                if (email.isEmpty() || password.isEmpty()) {
                    Toast.makeText(MainActivity.this, "Email and Password cannot be empty", Toast.LENGTH_SHORT).show();
                    return;
                }

                // Construct the URL with dynamic username and password
                String url = String.format("https://shubhammali2.xecurify.com/moas/rest/oauth/token?grant_type=password&client_secret=g9aidE_82IAGxtXpOKS7DayKXZg&client_id=AsqTQSlz9peWhDo&username=%s&password=%s", email, password);
                Log.d("myapp", "Making post request on token endpoint url: "+url);


                // Fetch access and refresh token from the token endpoint
                fetchDataFromUrl(url, new ResponseCallback() {
                    @Override
                    public void onSuccess(String access_token) {

                        // Make another API call with the access token

                        String userInfoUrl = "https://shubhammali2.xecurify.com/moas/rest/oauth/getuserinfo";
                        Log.d("myapp", "Making GET request at oauth/getuserinfo endpoint with url: "+userInfoUrl);
                        fetchUserInfo(userInfoUrl, access_token, new ResponseCallback() {
                            @Override
                            public void onSuccess(String response) {
                                Log.d("myapp", "Login Success using grant type password_grant");
                                Log.d("myapp", "response from getuserinfo : "+response);


                                // Start MainActivity2 with the user details
                                Intent intent = new Intent(MainActivity.this, MainActivity2.class);
                                intent.putExtra("userDetails", response);
                                startActivity(intent);
                                Log.d("myapp", "Redirected user to second activity ..");
                                finish(); // Close the current activity
                            }

                            @Override
                            public void onError(String error) {
                                Log.e("myapp", "Error occurred: " + error);
                            }
                        });
                    }

                    @Override
                    public void onError(String error) {
                        Toast.makeText(MainActivity.this, "Error: Invalid Username or Password", Toast.LENGTH_LONG).show();
                        Log.w("myapp","User entered Invalid username or password");
                    }
                });
            }
        });

    }//End of OnCreate Method```````````````````````````````````````

    private void reqForToken(String code) {
        String postUrl = "https://testshubham.miniorange.in/moas/rest/oauth/token?" +
                "grant_type=authorization_code" +
                "&client_id=VOPiLgXkIeH2gHc" +
                "&client_secret=1TYuX3TQNuHGKeWWaOEufqbJBMs" +
                "&redirect_uri=https://www.myapplication.com/v1/callback" +
                "&code=" + code;

        Log.d("myapp", "Making call on token endpoint with  post URL: " + postUrl);

        RequestQueue requestQueue = Volley.newRequestQueue(this);

        // Create the JsonObjectRequest
        JsonObjectRequest jsonObjectRequest = new JsonObjectRequest(Request.Method.POST, postUrl, null,
                new Response.Listener<JSONObject>() {
                    @Override
                    public void onResponse(JSONObject response) {
                        Log.d("myapp", "Response received ... : " + response.toString());
                        String idToken = null;
                        try {
                            //extracting id token from received jwt token
                            idToken = response.getString("id_token");
                        } catch (JSONException e) {
                            Log.e("myapp","error extracting id token from response"+e);
                            throw new RuntimeException(e);
                        }
                        String pemCertificate = "-----BEGIN PUBLIC KEY-----\n" +
                                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzIKQ+V528e3nGaOL72XA\n" +
                                "avmL2HAXwdG5+0Cg2X+ezPfSn2U+DxbYOKFyHXfdCj4ocgF1MKk1ECUDhMlZ6vsl\n" +
                                "m7ZPuq9Nus6cYeBxSFdKXaC+vI0hpghkGwAl7a6YT4HAbZ3qs+T7My5gaeuXI1j+\n" +
                                "8KBOXK8VRDormzQlI0Q+qbfqUSMCNBMsknxFWfgxvvXSBqEOV2Yq0hbp+JSrsB1S\n" +
                                "9DefmvNmxUKLDQ65MmInZ7HqfE+ocWt6H0ba9zISCgjSEs4m0fY6fr99EhuQ9vKX\n" +
                                "GcxQfvu2qAOHz0te4yQ67xoUGWzMCmZG3TUTfYz+kFVCSJSrmSnTzkppffio7ooA\n" +
                                "owIDAQAB\n" +
                                "-----END PUBLIC KEY-----\n";
                        try {
                            PublicKey publicKey = JwtUtils.getPublicKeyFromPem(pemCertificate);
                            if (JwtUtils.verifySignature(idToken, publicKey)) {
                                String payload = JwtUtils.decodePayload(idToken);
                                Log.d("myapp", "Payload decrypted success: " + payload);
                                // Start MainActivity2 with the user details
                                Intent intent = new Intent(MainActivity.this, MainActivity2.class);
                                intent.putExtra("userDetails", payload);
                                startActivity(intent);
                                Log.d("myapp", "Redirected user to second activity ..");
                                finish(); // Close the current activity
                            } else {
                                Log.e("myapp","invalid token error");
                            }
                        } catch (Exception e) {
                            e.printStackTrace();
                            Log.e("myapp","error occurred "+e);
                        }
                    }
                }, new Response.ErrorListener() {
            @Override
            public void onErrorResponse(VolleyError error) {
                // Handle the error
                NetworkResponse networkResponse = error.networkResponse;
                Log.e("myapp", "Status code: " + networkResponse.statusCode + " Response : "+ new String(networkResponse.data));
                retry(); //if login fails retry
            }
        });
        requestQueue.add(jsonObjectRequest);
    }

    private void fetchDataFromUrl(String url, ResponseCallback callback) {
        RequestQueue requestQueue = Volley.newRequestQueue(this);

        JsonObjectRequest jsonObjectRequest = new JsonObjectRequest(Request.Method.POST, url, null,
                new Response.Listener<JSONObject>() {
                    @Override
                    public void onResponse(JSONObject response) {
                        try {
                            String access_token = response.getString("access_token");
                            String refresh_token = response.getString("refresh_token"); //not needed for now
                            callback.onSuccess(access_token); //sending access token using callback on success
                            Log.d("myapp", "Access token Received : "+access_token);
                        } catch (JSONException e) {
                            callback.onError("JSON parsing error: " + e.getMessage());
                        }
                    }
                },
                new Response.ErrorListener() {
                    @Override
                    public void onErrorResponse(VolleyError error) {
                        callback.onError("Request error: " + error.getMessage());
                    }
                }
        );
        requestQueue.add(jsonObjectRequest);
    }

    private void fetchUserInfo(String url, String token, ResponseCallback callback) {
        RequestQueue requestQueue = Volley.newRequestQueue(this);

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
            public Map<String, String> getHeaders() throws AuthFailureError {
                Map<String, String> headers = new HashMap<>();
                headers.put("Authorization", "Bearer " + token);
                return headers;
            }
        };

        requestQueue.add(stringRequest);
    }

    interface ResponseCallback {
        void onSuccess(String response);

        void onError(String error);
    }

    private void retry(){ //if login fails retry````````````````````````````````````
        String url = "https://shubhammali2.xecurify.com/moas/idp/openidsso?client_id=AsqTQSlz9peWhDo&redirect_uri=https://www.myapplication.com/v1/callback&scope=email openid&response_type=code&state=abcd";
        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.setData(Uri.parse(url));
        startActivity(intent);
        Log.d("myapp", "OAuth initiated ...");

    }

}
class JwtUtils {

    static {
        // Add the BouncyCastle Provider once during class loading
        Security.addProvider(new BouncyCastleProvider());
    }

    // Split JWT into its three parts
    public static String[] splitToken(String jwt) throws IllegalArgumentException {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWT token format.");
        }
        return parts;
    }

    // Load PEM public key and get PublicKey object
    public static PublicKey getPublicKeyFromPem(String pem) throws Exception {
        if (pem == null || pem.isEmpty()) {
            throw new IllegalArgumentException("PEM string cannot be null or empty.");
        }

        try (PemReader pemReader = new PemReader(new StringReader(pem))) {
            PemObject pemObject = pemReader.readPemObject();
            if (pemObject == null) {
                throw new IllegalArgumentException("Invalid PEM format: Could not read PEM object.");
            }
            byte[] content = pemObject.getContent();

            X509EncodedKeySpec spec = new X509EncodedKeySpec(content);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (Exception e) {
            throw new Exception("Failed to parse PEM public key", e);
        }
    }

    // Verify JWT signature
    public static boolean verifySignature(String jwt, PublicKey publicKey) throws Exception {
        String[] parts = splitToken(jwt);
        String headerAndPayload = parts[0] + "." + parts[1];
        byte[] signature = decodeBase64Url(parts[2]);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(headerAndPayload.getBytes());
        return sig.verify(signature);
    }

    // Decode JWT payload
    public static String decodePayload(String jwt) {
        String[] splitToken = jwt.split("\\.");
        if (splitToken.length < 2) {
            throw new IllegalArgumentException("Invalid JWT token format.");
        }
        return new String(Base64.decode(splitToken[1], Base64.URL_SAFE));
    }

    // Decode Base64 URL-safe string
    public static byte[] decodeBase64Url(String base64Url) {
        return Base64.decode(base64Url, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
    }
}