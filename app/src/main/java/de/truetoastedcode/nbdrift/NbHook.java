package de.truetoastedcode.nbdrift;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.io.IOException;
import android.util.Log;
import android.os.Bundle;
import android.os.Environment;
import android.app.Activity;
import android.content.Context;
import android.text.TextUtils;
import java.util.Map;
import java.util.HashMap;
import java.lang.reflect.*;

/**
 * NbHook - Runtime hook for BaseParametersInterceptor with simulated response support
 * 
 * This class creates a runtime hook for the BaseParametersInterceptor class
 * from the Ninebot application. It intercepts HTTP requests to inject additional
 * parameters, handles response decryption, and can simulate responses for certain URLs.
 * 
 * The hook replicates the original intercept() method functionality using
 * Java reflection to access private methods and fields at runtime.
 */
public class NbHook {
    // === SIMULATED RESPONSE CONFIGURATION ===
    // Map to store URL patterns and their corresponding simulated responses
    private final Map<String, SimulatedResponse> simulatedResponses = new HashMap<>();
    
    /**
     * Functional interface for simulated response callbacks
     */
    public interface SimulatedResponseCallback {
        void onResponseAccessed(SimulatedResponse thizz, String url, Object request);
    }
    
    /**
     * Data class to hold simulated response information
     */
    public static class SimulatedResponse {
        public String body;
        public int statusCode;
        public String contentType;
        public Map<String, String> headers;
        public SimulatedResponseCallback callback;
        
        public SimulatedResponse(String body, int statusCode, String contentType) {
            this(body, statusCode, contentType, new HashMap<>(), null);
        }
        
        public SimulatedResponse(String body, int statusCode, String contentType, Map<String, String> headers) {
            this(body, statusCode, contentType, headers, null);
        }
        
        public SimulatedResponse(String body, int statusCode, String contentType, SimulatedResponseCallback callback) {
            this(body, statusCode, contentType, new HashMap<>(), callback);
        }

        public SimulatedResponse(String body, int statusCode, SimulatedResponseCallback callback) {
            this(body, statusCode, "application/json", new HashMap<>(), callback);
        }

        public SimulatedResponse(String body, String contentType) {
            this(body, 200, contentType, new HashMap<>(), null);
        }
        
        public SimulatedResponse(String body, String contentType, Map<String, String> headers) {
            this(body, 200, contentType, headers, null);
        }
        
        public SimulatedResponse(String body, String contentType, SimulatedResponseCallback callback) {
            this(body, 200, contentType, new HashMap<>(), callback);
        }

        public SimulatedResponse(String body, SimulatedResponseCallback callback) {
            this(body, 200, "application/json", new HashMap<>(), callback);
        }

        public SimulatedResponse(String body) {
            this(body, 200, "application/json", new HashMap<>(), null);
        }
        
        public SimulatedResponse(String body, int statusCode, String contentType, Map<String, String> headers, SimulatedResponseCallback callback) {
            this.body = body;
            this.statusCode = statusCode;
            this.contentType = contentType;
            this.headers = headers;
            this.callback = callback;
        }
        
        /**
         * Executes the callback if one is provided
         * 
         * @param url The URL that was intercepted
         * @param request The original request object
         */
        public void executeCallback(String url, Object request) {
            if (callback != null) {
                try {
                    callback.onResponseAccessed(this, url, request);
                } catch (Exception e) {
                    Log.e(EntryPoint.TAG, "Error executing simulated response callback: " + e);
                    e.printStackTrace();
                }
            }
        }
    }

    // === CLASS REFERENCES ===
    // All the Class<?> objects we need to access at runtime
    private Class<?>
    BaseParametersInterceptorClass,                    // Main interceptor class we're hooking
    BaseParametersInterceptorParametersProviderClass,  // Inner interface for parameter providers
    RequestClass,                                      // OkHttp Request class
    RequestBuilderClass,                               // OkHttp Request.Builder class  
    RequestBodyClass,                                  // OkHttp RequestBody class
    ResponseClass,                                     // OkHttp Response class
    ResponseBuilderClass,                              // OkHttp Response.Builder class
    ResponseBodyClass,                                 // OkHttp ResponseBody class
    MediaTypeClass,                                    // OkHttp MediaType class
    HttpUrlClass,                                      // OkHttp HttpUrl class
    HttpUrlBuilderClass,
    FormBodyBuilderClass,                              // OkHttp FormBody.Builder class
    InterceptorChainClass,                             // OkHttp Interceptor.Chain class
    BufferClass,                                       // Okio Buffer class
    BufferedSourceClass,                               // Okio BufferedSource class
    CharsetClass,                                      // Java Charset class
    JSONObjectClass,                                   // JSON Object class
    ProtocolClass,                                     // OkHttp Protocol class
    HeadersBuilderClass;                               // OkHttp Headers.Builder class

    // === METHOD REFERENCES ===
    // All the Method objects we need to invoke at runtime
    private Method
    BaseParametersInterceptorInterceptMeth,                      // Main intercept method we're hooking
    BaseParametersInterceptorIsCanInjectToBodyMeth,             // Checks if we can inject params to body
    BaseParametersInterceptorBodyToStringMeth,                  // Converts RequestBody to String
    BaseParametersInterceptorEncodeMeth,                        // Encodes body parameters (encryption)
    BaseParametersInterceptorConvertJsonMeth,
    FormBodyBuilderAddMeth,                                     // Adds key-value pair to form body
    FormBodyBuilderBuildMeth,                                   // Builds the form body
    MediaTypeParseMeth,                                         // Parses media type string
    RequestBodyCreateMeth,                                      // Creates RequestBody with content
    RequestBuilderPostMeth,                                     // Sets POST method on request builder
    RequestBuilderSetUrlMeth,
    InterceptorChainRequestMeth,                                // Gets request from interceptor chain
    InterceptorChainProceedMeth,                                // Proceeds with request in chain
    RequestNewBuilderMeth,                                      // Creates new request builder
    RequestBodyMeth,                                            // Gets body from request
    RequestHeaderMeth,                                          // Gets header value from request
    RequestUrlMeth,                                             // Gets the url from request
    HttpUrlEncodedPath,                                         // Gets the encoded path from httpurl
    HttpUrlToStringMeth,                                        // Gets string representation of URL
    HttpUrlNewBuilderMeth,
    HttpUrlBuilderSetSchemeMeth,
    HttpUrlBuilderBuildMeth,
    BaseParametersInterceptorParametersProviderParametersMeth,  // Gets parameters from provider
    RequestBuilderBuildMeth,                                    // Builds the request
    ResponseNewBuilderMeth,                                     // Creates new response builder
    ResponseBodyMeth,                                           // Gets body from response
    ResponseBodySourceMeth,                                     // Gets buffered source from response body
    ResponseBodyContentTypeMeth,                                // Gets content type from response body
    ResponseBodyCreateMeth,                                     // Creates new response body
    BufferedSourceRequestMeth,                                  // Requests data from buffered source
    BufferedSourceGetBufferMeth,                                // Gets buffer from buffered source
    BufferCloneMeth,                                           // Clones a buffer
    BufferReadStringMeth,                                      // Reads string from buffer
    MediaTypeCharsetMeth,                                      // Gets/sets charset on media type
    CharsetForNameMeth,                                        // Gets charset by name
    ResponseBuilderCodeMeth,                                   // Sets response code
    ResponseBuilderMessageMeth,                                // Sets response message
    ResponseBuilderProtocolMeth,                               // Sets response protocol
    ResponseBuilderHeadersMeth,                                // Sets response headers
    ResponseBuilderBodyMeth,                                   // Sets response body
    ResponseBuilderBuildMeth,                                  // Builds response
    ResponseBuilderNetworkResponseMeth,
    ResponseBuilderSentRequestAtMillisMeth,
    ResponseBuilderReceivedResponseAtMillisMeth,
    HeadersBuilderAddMeth,                                     // Adds header to headers builder
    HeadersBuilderBuildMeth,                                   // Builds headers
    MainActivityOnCreateMeth;

    // === FIELD REFERENCES ===
    // All the Field objects we need to access at runtime
    private Field
    mBodyParamsProviderField,  // Field holding the parameter provider instance
    mEncryptField,             // Field holding the encryption/decryption handler
    decryptAllField,           // Boolean field indicating if all responses should be decrypted
    keyDecryptField;           // Static field containing the decrypt header key constant

    // === CONSTRUCTOR REFERENCES ===
    private Constructor<?>
    FormBodyBuilderConst,      // Constructor for FormBody.Builder
    HeadersBuilderConst,       // Constructor for Headers.Builder
    ResponseBuilderConst;      // Constructor for Response.Builder

    // === RUNTIME VALUES ===
    private String KEY_DECRYPT;  // The decrypt header key extracted from original class at runtime
    private Object HTTP_1_1_PROTOCOL;  // HTTP/1.1 protocol constant

    /**
     * Constructor - initializes the hook by setting up all reflection references
     * and installing the method hook on BaseParametersInterceptor.intercept()
     */
    public NbHook() {
        hookBaseParamsInterc();

        addSimulatedResponse(
            "/app-api/app-version/v1/check",
            "{\"code\":1,\"desc\":\"Successfully\",\"data\":{\"latest_version\":null,\"version_name\":null,\"version_dec\":null,\"jump_type\":null,\"is_update\":0,\"is_force\":0,\"force_update_version\":null,\"popup_title\":null,\"button_sure\":null,\"button_cance\":null,\"load_url\":null},\"t\":0}"
        );

        String fwIotPayload = null;

        if (SimpleStorageChecker.canAccessStorage()) {
            Path payloadPath = Paths.get(
                Environment.getExternalStorageDirectory().getAbsolutePath(),
                "nbdrift",
                "fw-iot.json"
            );
            if (Files.exists(payloadPath)) {
                try {
                    fwIotPayload = new String(Files.readAllBytes(payloadPath));
                } catch (IOException e) {
                    Log.e(EntryPoint.TAG, "Error reading payload file: " + e.getMessage(), e);
                }
            } else {
                Log.d(EntryPoint.TAG, "Payload file does not exist at: " + payloadPath.toString());
            }
        } else {
            Log.e(EntryPoint.TAG, "Cannot access storage. Permission may be missing.");
        }

        if (fwIotPayload != null) {
            addSimulatedResponse("/vehicle/firmware/get-last-version-iot", fwIotPayload);
        }
    }

    /**
     * Adds a simulated response for a specific URL pattern
     * 
     * @param urlPattern The URL pattern to match (supports contains matching)
     * @param responseBody The response body to return
     * @param statusCode The HTTP status code (e.g., 200, 404, 500)
     * @param contentType The content type (e.g., "application/json", "text/plain")
     */
    public void addSimulatedResponse(String urlPattern, String responseBody, int statusCode, String contentType) {
        simulatedResponses.put(urlPattern, new SimulatedResponse(responseBody, statusCode, contentType));
        Log.d(EntryPoint.TAG, "Added simulated response for pattern: " + urlPattern);
    }

    /**
     * Adds a simulated response for a specific URL pattern with custom headers
     * 
     * @param urlPattern The URL pattern to match (supports contains matching)
     * @param responseBody The response body to return
     * @param statusCode The HTTP status code (e.g., 200, 404, 500)
     * @param contentType The content type (e.g., "application/json", "text/plain")
     * @param headers Additional headers to include in the response
     */
    public void addSimulatedResponse(String urlPattern, String responseBody, int statusCode, String contentType, Map<String, String> headers) {
        simulatedResponses.put(urlPattern, new SimulatedResponse(responseBody, statusCode, contentType, headers));
        Log.d(EntryPoint.TAG, "Added simulated response for pattern: " + urlPattern);
    }

    /**
     * Adds a simulated response for a specific URL pattern with a callback
     * 
     * @param urlPattern The URL pattern to match (supports contains matching)
     * @param responseBody The response body to return
     * @param statusCode The HTTP status code (e.g., 200, 404, 500)
     * @param contentType The content type (e.g., "application/json", "text/plain")
     * @param callback Lambda function to execute when this response is accessed
     */
    public void addSimulatedResponse(String urlPattern, String responseBody, int statusCode, String contentType, SimulatedResponseCallback callback) {
        simulatedResponses.put(urlPattern, new SimulatedResponse(responseBody, statusCode, contentType, callback));
        Log.d(EntryPoint.TAG, "Added simulated response with callback for pattern: " + urlPattern);
    }

    /**
     * Adds a simulated response for a specific URL pattern with custom headers and a callback
     * 
     * @param urlPattern The URL pattern to match (supports contains matching)
     * @param responseBody The response body to return
     * @param statusCode The HTTP status code (e.g., 200, 404, 500)
     * @param contentType The content type (e.g., "application/json", "text/plain")
     * @param headers Additional headers to include in the response
     * @param callback Lambda function to execute when this response is accessed
     */
    public void addSimulatedResponse(String urlPattern, String responseBody, int statusCode, String contentType, Map<String, String> headers, SimulatedResponseCallback callback) {
        simulatedResponses.put(urlPattern, new SimulatedResponse(responseBody, statusCode, contentType, headers, callback));
        Log.d(EntryPoint.TAG, "Added simulated response with headers and callback for pattern: " + urlPattern);
    }

    /**
     * Adds a simulated response for a specific URL pattern with callback (defaults to JSON content type)
     * 
     * @param urlPattern The URL pattern to match (supports contains matching)
     * @param responseBody The response body to return
     * @param statusCode The HTTP status code (e.g., 200, 404, 500)
     * @param callback Lambda function to execute when this response is accessed
     */
    public void addSimulatedResponse(String urlPattern, String responseBody, int statusCode, SimulatedResponseCallback callback) {
        simulatedResponses.put(urlPattern, new SimulatedResponse(responseBody, statusCode, callback));
        Log.d(EntryPoint.TAG, "Added simulated response with callback for pattern: " + urlPattern);
    }

    /**
     * Adds a simulated response for a specific URL pattern (defaults to 200 status code)
     * 
     * @param urlPattern The URL pattern to match (supports contains matching)
     * @param responseBody The response body to return
     * @param contentType The content type (e.g., "application/json", "text/plain")
     */
    public void addSimulatedResponse(String urlPattern, String responseBody, String contentType) {
        simulatedResponses.put(urlPattern, new SimulatedResponse(responseBody, contentType));
        Log.d(EntryPoint.TAG, "Added simulated response for pattern: " + urlPattern);
    }

    /**
     * Adds a simulated response for a specific URL pattern with custom headers (defaults to 200 status code)
     * 
     * @param urlPattern The URL pattern to match (supports contains matching)
     * @param responseBody The response body to return
     * @param contentType The content type (e.g., "application/json", "text/plain")
     * @param headers Additional headers to include in the response
     */
    public void addSimulatedResponse(String urlPattern, String responseBody, String contentType, Map<String, String> headers) {
        simulatedResponses.put(urlPattern, new SimulatedResponse(responseBody, contentType, headers));
        Log.d(EntryPoint.TAG, "Added simulated response with headers for pattern: " + urlPattern);
    }

    /**
     * Adds a simulated response for a specific URL pattern with callback (defaults to 200 status code)
     * 
     * @param urlPattern The URL pattern to match (supports contains matching)
     * @param responseBody The response body to return
     * @param contentType The content type (e.g., "application/json", "text/plain")
     * @param callback Lambda function to execute when this response is accessed
     */
    public void addSimulatedResponse(String urlPattern, String responseBody, String contentType, SimulatedResponseCallback callback) {
        simulatedResponses.put(urlPattern, new SimulatedResponse(responseBody, contentType, callback));
        Log.d(EntryPoint.TAG, "Added simulated response with callback for pattern: " + urlPattern);
    }

    /**
     * Adds a simulated response for a specific URL pattern with callback (defaults to 200 status code and JSON content type)
     * 
     * @param urlPattern The URL pattern to match (supports contains matching)
     * @param responseBody The response body to return
     * @param callback Lambda function to execute when this response is accessed
     */
    public void addSimulatedResponse(String urlPattern, String responseBody, SimulatedResponseCallback callback) {
        simulatedResponses.put(urlPattern, new SimulatedResponse(responseBody, callback));
        Log.d(EntryPoint.TAG, "Added simulated response with callback for pattern: " + urlPattern);
    }

    /**
     * Adds a simulated response for a specific URL pattern with callback (defaults to 200 status code and JSON content type)
     * 
     * @param urlPattern The URL pattern to match (supports contains matching)
     * @param responseBody The response body to return
     */
    public void addSimulatedResponse(String urlPattern, String responseBody) {
        simulatedResponses.put(urlPattern, new SimulatedResponse(responseBody));
        Log.d(EntryPoint.TAG, "Added simulated response with callback for pattern: " + urlPattern);
    }

    /**
     * Removes a simulated response for a URL pattern
     * 
     * @param urlPattern The URL pattern to remove
     */
    public void removeSimulatedResponse(String urlPattern) {
        simulatedResponses.remove(urlPattern);
        Log.d(EntryPoint.TAG, "Removed simulated response for pattern: " + urlPattern);
    }

    /**
     * Clears all simulated responses
     */
    public void clearSimulatedResponses() {
        simulatedResponses.clear();
        Log.d(EntryPoint.TAG, "Cleared all simulated responses");
    }

    /**
     * Checks if a URL matches any of the configured simulated response patterns
     * 
     * @param url The URL to check
     * @return The matching SimulatedResponse or null if no match
     */
    private SimulatedResponse getSimulatedResponseForUrl(String url) {
        for (Map.Entry<String, SimulatedResponse> entry : simulatedResponses.entrySet()) {
            if (url.contains(entry.getKey())) {
                return entry.getValue();
            }
        }
        return null;
    }

    /**
     * Creates a simulated HTTP response
     * 
     * @param request The original request
     * @param simulatedResp The simulated response configuration
     * @return A mock HTTP response object
     */
    private Object createSimulatedResponse(Object request, SimulatedResponse simulatedResp) {
        try {
            if (request == null) {
                throw new IllegalArgumentException("request() == null");
            }

            // Create response body with the simulated content
            Object mediaType = MediaTypeParseMeth.invoke(null, simulatedResp.contentType);
            Object responseBody = ResponseBodyCreateMeth.invoke(null, simulatedResp.body, mediaType);

            // Create headers builder and add custom headers
            Object headersBuilder = HeadersBuilderConst.newInstance();
            HeadersBuilderAddMeth.invoke(headersBuilder, "Content-Type", simulatedResp.contentType);
            HeadersBuilderAddMeth.invoke(headersBuilder, "Content-Length", String.valueOf(simulatedResp.body.length()));
            for (Map.Entry<String, String> header : simulatedResp.headers.entrySet()) {
                HeadersBuilderAddMeth.invoke(headersBuilder, header.getKey(), header.getValue());
            }
            Object headers = HeadersBuilderBuildMeth.invoke(headersBuilder);

            // Create a networkResponse with no body
            Object networkResponseBuilder = ResponseBuilderConst.newInstance();
            ResponseBuilderCodeMeth.invoke(networkResponseBuilder, simulatedResp.statusCode);
            ResponseBuilderMessageMeth.invoke(networkResponseBuilder, getStatusMessage(simulatedResp.statusCode));
            ResponseBuilderProtocolMeth.invoke(networkResponseBuilder, HTTP_1_1_PROTOCOL);
            ResponseBuilderHeadersMeth.invoke(networkResponseBuilder, headers);
            // Set the request on networkResponseBuilder
            Method requestMethod = ResponseBuilderClass.getMethod("request", RequestClass);
            requestMethod.invoke(networkResponseBuilder, request);
            // No body set for networkResponse to comply with OkHttp constraints
            Object networkResponse = ResponseBuilderBuildMeth.invoke(networkResponseBuilder);

            // Build the main response
            Object responseBuilder = ResponseBuilderConst.newInstance();
            ResponseBuilderCodeMeth.invoke(responseBuilder, simulatedResp.statusCode);
            ResponseBuilderMessageMeth.invoke(responseBuilder, getStatusMessage(simulatedResp.statusCode));
            ResponseBuilderProtocolMeth.invoke(responseBuilder, HTTP_1_1_PROTOCOL);
            ResponseBuilderHeadersMeth.invoke(responseBuilder, headers);
            ResponseBuilderBodyMeth.invoke(responseBuilder, responseBody);
            ResponseBuilderNetworkResponseMeth.invoke(responseBuilder, networkResponse);

            // Set timing fields
            long currentTime = System.currentTimeMillis();
            ResponseBuilderSentRequestAtMillisMeth.invoke(responseBuilder, currentTime - 100);
            ResponseBuilderReceivedResponseAtMillisMeth.invoke(responseBuilder, currentTime);

            // Set the request on the response
            requestMethod.invoke(responseBuilder, request);

            return ResponseBuilderBuildMeth.invoke(responseBuilder);
        } catch (Exception e) {
            Log.e(EntryPoint.TAG, "createSimulatedResponse(): [error] " + Log.getStackTraceString(e));
            return null;
        }
    }

    /**
     * Gets the standard HTTP status message for a status code
     * 
     * @param statusCode The HTTP status code
     * @return The corresponding status message
     */
    private String getStatusMessage(int statusCode) {
        switch (statusCode) {
            case 200: return "OK";
            case 201: return "Created";
            case 204: return "No Content";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 500: return "Internal Server Error";
            case 502: return "Bad Gateway";
            case 503: return "Service Unavailable";
            default: return "Unknown";
        }
    }

    /**
     * Main hook method that replaces BaseParametersInterceptor.intercept()
     * 
     * This method replicates the original intercept logic with added simulated response support:
     * 1. Checks if the URL matches any simulated response patterns
     * 2. If yes, returns the simulated response without making a real request
     * 3. If no, continues with the original logic:
     *    - Checks if additional parameters can be injected into the request body
     *    - If yes, adds parameters from the provider and encodes/encrypts the body
     *    - Proceeds with the HTTP request
     *    - Checks if the response needs decryption based on headers or settings
     *    - If yes, decrypts the response body and returns modified response
     * 
     * @param callback The method callback containing original method and arguments
     * @return The processed HTTP response (potentially simulated or with decrypted body)
     */
    public Object myIntercept(Hooker.MethodCallback callback) {
        try {
            // === REQUEST SETUP ===
            // Extract the interceptor instance and chain from callback arguments
            Object
            thizz = callback.args[0],  // The BaseParametersInterceptor instance
            chain = callback.args[1];  // The OkHttp Interceptor.Chain

            // Get the original request and create a builder for modifications
            Object
            request = InterceptorChainRequestMeth.invoke(chain),
            reqBuilder = RequestNewBuilderMeth.invoke(request);

            // === CHECK FOR SIMULATED RESPONSE ===
            // Get the request URL and check if it matches any simulated response patterns
            Object requestUrl = RequestUrlMeth.invoke(request);
            String urlString = (String) HttpUrlToStringMeth.invoke(requestUrl);

            SimulatedResponse simulatedResp = getSimulatedResponseForUrl(urlString);
            if (simulatedResp != null) {
                Object urlBuilder = HttpUrlNewBuilderMeth.invoke(requestUrl);
                HttpUrlBuilderSetSchemeMeth.invoke(urlBuilder, "http");
                Object newRequestUrl = HttpUrlBuilderBuildMeth.invoke(urlBuilder);
                RequestBuilderSetUrlMeth.invoke(reqBuilder, newRequestUrl);
                Log.d(EntryPoint.TAG, "Changed URL scheme to HTTP for simulated response.");
            }

            // === REQUEST BODY PARAMETER INJECTION ===
            // Check if we can inject additional parameters into the request body
            // This only works for POST requests with form-encoded content
            boolean canInjectToBody = (Boolean) BaseParametersInterceptorIsCanInjectToBodyMeth.invoke(thizz, request);
            String bodyStr = null;

            if (canInjectToBody) {
                // Convert existing request body to string format
                bodyStr = (String) BaseParametersInterceptorBodyToStringMeth.invoke(thizz, RequestBodyMeth.invoke(request));

                // Get the parameter provider from the interceptor instance
                Object paramsProvider = mBodyParamsProviderField.get(thizz);

                Map<?, ?> params;

                // If provider exists and has parameters, add them to the request
                if (
                    paramsProvider != null &&
                    (params = (Map<?, ?>) BaseParametersInterceptorParametersProviderParametersMeth.invoke(paramsProvider)) != null &&
                    params.size() > 0
                ) {
                    // Create a new form body builder to add the additional parameters
                    Object formBuilder = FormBodyBuilderConst.newInstance();

                    // Add each parameter to the form builder
                    for (Map.Entry<?, ?> entry : params.entrySet()) {
                        FormBodyBuilderAddMeth.invoke(formBuilder, entry.getKey(), entry.getValue());
                    }

                    // Convert the additional parameters to string and append to existing body
                    String additionalParams = (String) BaseParametersInterceptorBodyToStringMeth.invoke(
                        thizz, FormBodyBuilderBuildMeth.invoke(formBuilder));
                    
                    // Combine original body with additional parameters using '&' separator
                    bodyStr = bodyStr + (bodyStr.length() > 0 ? "&" : "") + additionalParams;
                }

                // === REQUEST BODY ENCODING/ENCRYPTION ===
                // Try to encode/encrypt the body parameters (may return null if no encryption)
                String encodedBodyStr = (String) BaseParametersInterceptorEncodeMeth.invoke(thizz, bodyStr);

                // Create the appropriate request body based on whether encoding was applied
                Object mediaType, reqBody;
                
                if (encodedBodyStr != null) {
                    // Encoded body uses HTML content type
                    mediaType = MediaTypeParseMeth.invoke(null, "text/html;charset=UTF-8");
                    reqBody = RequestBodyCreateMeth.invoke(null, encodedBodyStr, mediaType);
                } else {
                    // Non-encoded body uses form URL encoded content type
                    mediaType = MediaTypeParseMeth.invoke(null, "application/x-www-form-urlencoded;charset=UTF-8");
                    reqBody = RequestBodyCreateMeth.invoke(null, bodyStr, mediaType);
                }

                // Set the modified body on the request builder
                RequestBuilderPostMeth.invoke(reqBuilder, reqBody);
            }

            // === HTTP REQUEST EXECUTION ===
            // Build the final request
            Object builtRequest = RequestBuilderBuildMeth.invoke(reqBuilder);

            if (simulatedResp != null) {
                Log.d(EntryPoint.TAG, "Returning simulated response for URL: " + urlString);
                
                // Execute the callback if one is provided
                simulatedResp.executeCallback(urlString, builtRequest);
                
                Object simulatedResponse = createSimulatedResponse(builtRequest, simulatedResp);
                
                if (simulatedResponse != null) {
                    // Log the simulated response
                    Log.d(EntryPoint.TAG, String.format(
                        "######## BEGIN SIMULATED REQUEST ########\n%s\n%s\n<simulated>\n%s\n%s\n######## END SIMULATED REQUEST ########",
                        (String) HttpUrlEncodedPath.invoke(requestUrl),
                        builtRequest,
                        simulatedResponse,
                        simulatedResp.body
                    ));
                    
                    return simulatedResponse;
                }
                
                Log.w(EntryPoint.TAG, "Failed to create simulated response, falling back to real request");
            }

            // execute it through the chain
            Object response = InterceptorChainProceedMeth.invoke(chain, builtRequest);

            // === RESPONSE DECRYPTION HANDLING ===
            // Check if response decryption is needed based on request headers or global setting
            String header = (String) RequestHeaderMeth.invoke(builtRequest, KEY_DECRYPT);
            boolean decryptAll = decryptAllField.getBoolean(thizz);
            Object mEncrypt = mEncryptField.get(thizz);

            // Skip decryption if:
            // - decryptAll is false AND no decrypt header is present, OR
            // - no encryption handler is available
            if ((!decryptAll && TextUtils.isEmpty(header)) || mEncrypt == null) {
                return response;
            }

            // Get the response body for decryption
            Object responseBody = ResponseBodyMeth.invoke(response);
            if (responseBody == null) {
                return response;  // No body to decrypt
            }

            // === RESPONSE BODY EXTRACTION ===
            // Get the response content through OkIO's buffered source system
            Object source = ResponseBodySourceMeth.invoke(responseBody);
            BufferedSourceRequestMeth.invoke(source, Long.MAX_VALUE);  // Request all available data
            Object buffer = BufferedSourceGetBufferMeth.invoke(source);
            Object contentType = ResponseBodyContentTypeMeth.invoke(responseBody);

            // Set up UTF-8 charset for text processing
            Object utf8Charset = CharsetForNameMeth.invoke(null, "UTF-8");
            if (contentType != null) {
                MediaTypeCharsetMeth.invoke(contentType, utf8Charset);
            }

            // === RESPONSE DECRYPTION ===
            // Clone the buffer and read response as UTF-8 string
            Object clonedBuffer = BufferCloneMeth.invoke(buffer);
            String responseText = (String) BufferReadStringMeth.invoke(clonedBuffer, utf8Charset);

            // Call the decrypt method on the encryption handler
            Method decryptMethod = mEncrypt.getClass().getMethod("decrypt", String.class);
            String decryptedText = (String) decryptMethod.invoke(mEncrypt, responseText);

            // === RESPONSE RECONSTRUCTION ===
            // Create new response body with decrypted content
            Object newResponseBody = ResponseBodyCreateMeth.invoke(null, decryptedText, contentType);
            
            // Build new response with the decrypted body
            Object responseBuilder = ResponseNewBuilderMeth.invoke(response);
            ResponseBuilderBodyMeth.invoke(responseBuilder, newResponseBody);
            Object finalResponse = ResponseBuilderBuildMeth.invoke(responseBuilder);

            Object bodyJson = null;
            if (bodyStr != null) {
                bodyJson = BaseParametersInterceptorConvertJsonMeth.invoke(thizz, bodyStr);
            }

            Log.d(EntryPoint.TAG, String.format(
                "######## BEGIN REQUEST ########\n%s\n%s\n%s\n%s\n######## END REQUEST ########",
                builtRequest,
                (bodyJson == null) ? "<none>" : bodyJson,
                finalResponse,
                (decryptedText == null || decryptedText.isEmpty()) ? "<none>" : decryptedText
            ));

            return finalResponse;

        } catch (Exception e) {
            Log.e(EntryPoint.TAG, "myIntercept(): [error] " + e);
            e.printStackTrace();
            // === ERROR FALLBACK ===
            // If anything goes wrong, try to call the original method as fallback
            try {
                return callback.backup.invoke(callback.args[0], callback.args[1]);
            } catch (Exception fallbackError) {
                Log.e(EntryPoint.TAG, "Fallback failed: " + fallbackError);
                return null;
            }
        }
    }

    // public Object myNetworkResponse(Hooker.MethodCallback callback) {
    //     try {
    //         Object result = callback.backup.invoke(callback.args[0]);
    //         Log.d(EntryPoint.TAG, "myNetworkResponse(): " + (result == null ? "null" : "Object"));
    //         return result;
    //     } catch (Exception e) {
    //         Log.e(EntryPoint.TAG, "myNetworkResponse(): " + e.getMessage(), e);
    //         return null;
    //     }
    // }

    // public Object myCacheResponse(Hooker.MethodCallback callback) {
    //     try {
    //         Object result = callback.backup.invoke(callback.args[0]);
    //         Log.d(EntryPoint.TAG, "myCacheResponse(): " + (result == null ? "null" : "Object"));
    //         return result;
    //     } catch (Exception e) {
    //         Log.e(EntryPoint.TAG, "myCacheResponse(): " + e.getMessage(), e);
    //         return null;
    //     }
    // }

    // public Object myPriorResponse(Hooker.MethodCallback callback) {
    //     try {
    //         Object result = callback.backup.invoke(callback.args[0]);
    //         Log.d(EntryPoint.TAG, "myPriorResponse(): " + (result == null ? "null" : "Object"));
    //         return result;
    //     } catch (Exception e) {
    //         Log.e(EntryPoint.TAG, "myPriorResponse(): " + e.getMessage(), e);
    //         return null;
    //     }
    // }

    /**
     * Sets up all reflection references and installs the method hook
     * 
     * This method:
     * 1. Resolves all required class references using TypeResolver
     * 2. Gets all method references (both public and private with setAccessible)
     * 3. Gets all field references (private fields with setAccessible)
     * 4. Extracts runtime constants from the original class
     * 5. Installs the hook on the intercept method
     */
    private void hookBaseParamsInterc() {
        try {
            // === CLASS RESOLUTION ===
            // Resolve all class references we'll need for reflection
            BaseParametersInterceptorClass = TypeResolver.resolveClass("cn.ninebot.lib.network.interceptor.BaseParametersInterceptor");
            BaseParametersInterceptorParametersProviderClass = TypeResolver.resolveClass("cn.ninebot.lib.network.interceptor.BaseParametersInterceptor$ParametersProvider");
            RequestClass = TypeResolver.resolveClass("okhttp3.Request");
            RequestBuilderClass = TypeResolver.resolveClass("okhttp3.Request$Builder");
            RequestBodyClass = TypeResolver.resolveClass("okhttp3.RequestBody");
            ResponseClass = TypeResolver.resolveClass("okhttp3.Response");
            ResponseBuilderClass = TypeResolver.resolveClass("okhttp3.Response$Builder");
            ResponseBodyClass = TypeResolver.resolveClass("okhttp3.ResponseBody");
            MediaTypeClass = TypeResolver.resolveClass("okhttp3.MediaType");
            HttpUrlClass = TypeResolver.resolveClass("okhttp3.HttpUrl");
            HttpUrlBuilderClass = TypeResolver.resolveClass("okhttp3.HttpUrl$Builder");
            FormBodyBuilderClass = TypeResolver.resolveClass("okhttp3.FormBody$Builder");
            InterceptorChainClass = TypeResolver.resolveClass("okhttp3.Interceptor$Chain");
            BufferClass = TypeResolver.resolveClass("okio.Buffer");
            BufferedSourceClass = TypeResolver.resolveClass("okio.BufferedSource");
            CharsetClass = TypeResolver.resolveClass("java.nio.charset.Charset");
            JSONObjectClass = TypeResolver.resolveClass("org.json.JSONObject");
            ProtocolClass = TypeResolver.resolveClass("okhttp3.Protocol");
            HeadersBuilderClass = TypeResolver.resolveClass("okhttp3.Headers$Builder");
            
            // === METHOD RESOLUTION ===
            // Get all method references - some need setAccessible(true) for private methods
            BaseParametersInterceptorInterceptMeth = BaseParametersInterceptorClass.getMethod("intercept", InterceptorChainClass);
            BaseParametersInterceptorIsCanInjectToBodyMeth = BaseParametersInterceptorClass.getDeclaredMethod("isCanInjectToBody", RequestClass);
            BaseParametersInterceptorIsCanInjectToBodyMeth.setAccessible(true);
            BaseParametersInterceptorBodyToStringMeth = BaseParametersInterceptorClass.getDeclaredMethod("bodyToString", RequestBodyClass);
            BaseParametersInterceptorBodyToStringMeth.setAccessible(true);
            BaseParametersInterceptorEncodeMeth = BaseParametersInterceptorClass.getDeclaredMethod("encode", String.class);
            BaseParametersInterceptorEncodeMeth.setAccessible(true);
            BaseParametersInterceptorConvertJsonMeth = BaseParametersInterceptorClass.getDeclaredMethod("convertJson", String.class);
            BaseParametersInterceptorConvertJsonMeth.setAccessible(true);
            FormBodyBuilderAddMeth = FormBodyBuilderClass.getMethod("add", String.class, String.class);
            FormBodyBuilderBuildMeth = FormBodyBuilderClass.getMethod("build");
            MediaTypeParseMeth = MediaTypeClass.getMethod("parse", String.class);
            RequestBodyCreateMeth = RequestBodyClass.getMethod("create", String.class, MediaTypeClass);
            RequestBuilderPostMeth = RequestBuilderClass.getMethod("post", RequestBodyClass);
            RequestBuilderSetUrlMeth = RequestBuilderClass.getMethod("setUrl$okhttp", HttpUrlClass);
            InterceptorChainRequestMeth = InterceptorChainClass.getMethod("request");
            InterceptorChainProceedMeth = InterceptorChainClass.getMethod("proceed", RequestClass);
            RequestNewBuilderMeth = RequestClass.getMethod("newBuilder");
            RequestBodyMeth = RequestClass.getMethod("body");
            RequestHeaderMeth = RequestClass.getMethod("header", String.class);
            RequestUrlMeth = RequestClass.getMethod("url");
            HttpUrlEncodedPath = HttpUrlClass.getMethod("encodedPath");
            HttpUrlToStringMeth = HttpUrlClass.getMethod("toString");
            HttpUrlNewBuilderMeth = HttpUrlClass.getMethod("newBuilder");
            HttpUrlBuilderSetSchemeMeth = HttpUrlBuilderClass.getMethod("scheme", String.class);
            HttpUrlBuilderBuildMeth = HttpUrlBuilderClass.getMethod("build");
            BaseParametersInterceptorParametersProviderParametersMeth = BaseParametersInterceptorParametersProviderClass.getMethod("parameters");
            RequestBuilderBuildMeth = RequestBuilderClass.getMethod("build");
            ResponseNewBuilderMeth = ResponseClass.getMethod("newBuilder");
            ResponseBodyMeth = ResponseClass.getMethod("body");
            ResponseBodySourceMeth = ResponseBodyClass.getMethod("source");
            ResponseBodyContentTypeMeth = ResponseBodyClass.getMethod("contentType");
            ResponseBodyCreateMeth = ResponseBodyClass.getMethod("create", String.class, MediaTypeClass);
            BufferedSourceRequestMeth = BufferedSourceClass.getMethod("request", long.class);
            BufferedSourceGetBufferMeth = BufferedSourceClass.getMethod("getBuffer");
            BufferCloneMeth = BufferClass.getMethod("clone");
            BufferReadStringMeth = BufferClass.getMethod("readString", CharsetClass);
            MediaTypeCharsetMeth = MediaTypeClass.getMethod("charset", CharsetClass);
            CharsetForNameMeth = CharsetClass.getMethod("forName", String.class);
            ResponseBuilderCodeMeth = ResponseBuilderClass.getMethod("code", int.class);
            ResponseBuilderMessageMeth = ResponseBuilderClass.getMethod("message", String.class);
            ResponseBuilderProtocolMeth = ResponseBuilderClass.getMethod("protocol", ProtocolClass);
            ResponseBuilderHeadersMeth = ResponseBuilderClass.getMethod("headers", TypeResolver.resolveClass("okhttp3.Headers"));
            ResponseBuilderBodyMeth = ResponseBuilderClass.getMethod("body", ResponseBodyClass);
            ResponseBuilderBuildMeth = ResponseBuilderClass.getMethod("build");
            ResponseBuilderNetworkResponseMeth = ResponseBuilderClass.getMethod("networkResponse", ResponseClass);
            ResponseBuilderSentRequestAtMillisMeth = ResponseBuilderClass.getMethod("sentRequestAtMillis", long.class);
            ResponseBuilderReceivedResponseAtMillisMeth = ResponseBuilderClass.getMethod("receivedResponseAtMillis", long.class);
            HeadersBuilderAddMeth = HeadersBuilderClass.getMethod("add", String.class, String.class);
            HeadersBuilderBuildMeth = HeadersBuilderClass.getMethod("build");

            // === FIELD RESOLUTION ===
            // Get all field references - all are private so need setAccessible(true)
            mBodyParamsProviderField = BaseParametersInterceptorClass.getDeclaredField("mBodyParamsProvider");
            mBodyParamsProviderField.setAccessible(true);
            mEncryptField = BaseParametersInterceptorClass.getDeclaredField("mEncrypt");
            mEncryptField.setAccessible(true);
            decryptAllField = BaseParametersInterceptorClass.getDeclaredField("decryptAll");
            decryptAllField.setAccessible(true);
            keyDecryptField = BaseParametersInterceptorClass.getDeclaredField("KEY_DECRYPT");
            keyDecryptField.setAccessible(true);

            // === RUNTIME CONSTANT EXTRACTION ===
            // Extract the decrypt header key constant from the original class at runtime
            // This ensures we always use the same value as the original code
            KEY_DECRYPT = (String) keyDecryptField.get(null);

            // Get HTTP/1.1 protocol constant
            Field http11Field = ProtocolClass.getDeclaredField("HTTP_1_1");
            HTTP_1_1_PROTOCOL = http11Field.get(null);

            // === CONSTRUCTOR RESOLUTION ===
            FormBodyBuilderConst = FormBodyBuilderClass.getConstructor();
            HeadersBuilderConst = HeadersBuilderClass.getConstructor();
            ResponseBuilderConst = ResponseBuilderClass.getConstructor();

            // === HOOK INSTALLATION ===
            // Install our hook method to replace the original intercept method
            Hooker interceptHooker = Hooker.hook(
                BaseParametersInterceptorInterceptMeth,
                this.getClass().getMethod("myIntercept", Hooker.MethodCallback.class),
                this
            );

            // Verify hook installation succeeded
            if (interceptHooker == null) {
                throw new IllegalStateException("Failed to hook intercept method");
            }

            Log.d(EntryPoint.TAG, "BaseParametersInterceptor hook installed successfully with simulated response support!");

        } catch (Exception e) {
            Log.e(EntryPoint.TAG, "hookBaseParamsInterc(): [error] " + Log.getStackTraceString(e));
        }
    }
}
