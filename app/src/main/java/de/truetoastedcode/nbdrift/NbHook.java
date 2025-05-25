package de.truetoastedcode.nbdrift;

import android.util.Log;
import android.text.TextUtils;
import java.util.Map;
import java.lang.reflect.*;

/**
 * NbHook - Runtime hook for BaseParametersInterceptor
 * 
 * This class creates a runtime hook for the BaseParametersInterceptor class
 * from the Ninebot application. It intercepts HTTP requests to inject additional
 * parameters and handles response decryption.
 * 
 * The hook replicates the original intercept() method functionality using
 * Java reflection to access private methods and fields at runtime.
 */
public class NbHook {
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
    FormBodyBuilderClass,                              // OkHttp FormBody.Builder class
    InterceptorChainClass,                             // OkHttp Interceptor.Chain class
    BufferClass,                                       // Okio Buffer class
    BufferedSourceClass,                               // Okio BufferedSource class
    CharsetClass,                                      // Java Charset class
    JSONObjectClass;

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
    InterceptorChainRequestMeth,                                // Gets request from interceptor chain
    InterceptorChainProceedMeth,                                // Proceeds with request in chain
    RequestNewBuilderMeth,                                      // Creates new request builder
    RequestBodyMeth,                                            // Gets body from request
    RequestHeaderMeth,                                          // Gets header value from request
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
    CharsetForNameMeth;                                        // Gets charset by name

    // === FIELD REFERENCES ===
    // All the Field objects we need to access at runtime
    private Field
    mBodyParamsProviderField,  // Field holding the parameter provider instance
    mEncryptField,             // Field holding the encryption/decryption handler
    decryptAllField,           // Boolean field indicating if all responses should be decrypted
    keyDecryptField;           // Static field containing the decrypt header key constant

    // === CONSTRUCTOR REFERENCES ===
    private Constructor<?>
    FormBodyBuilderConst;      // Constructor for FormBody.Builder

    // === RUNTIME VALUES ===
    private String KEY_DECRYPT;  // The decrypt header key extracted from original class at runtime

    /**
     * Constructor - initializes the hook by setting up all reflection references
     * and installing the method hook on BaseParametersInterceptor.intercept()
     */
    public NbHook() {
        hookBaseParamsInterc();
    }

    /**
     * Main hook method that replaces BaseParametersInterceptor.intercept()
     * 
     * This method replicates the original intercept logic:
     * 1. Checks if additional parameters can be injected into the request body
     * 2. If yes, adds parameters from the provider and encodes/encrypts the body
     * 3. Proceeds with the HTTP request
     * 4. Checks if the response needs decryption based on headers or settings
     * 5. If yes, decrypts the response body and returns modified response
     * 
     * @param callback The method callback containing original method and arguments
     * @return The processed HTTP response (potentially with decrypted body)
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
            // Build the final request and execute it through the chain
            Object builtRequest = RequestBuilderBuildMeth.invoke(reqBuilder);
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
            Method responseBuilderBodyMethod = ResponseBuilderClass.getMethod("body", ResponseBodyClass);
            responseBuilderBodyMethod.invoke(responseBuilder, newResponseBody);
            
            Method responseBuilderBuildMethod = ResponseBuilderClass.getMethod("build");
            Object finalResponse = responseBuilderBuildMethod.invoke(responseBuilder);

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
            FormBodyBuilderClass = TypeResolver.resolveClass("okhttp3.FormBody$Builder");
            InterceptorChainClass = TypeResolver.resolveClass("okhttp3.Interceptor$Chain");
            BufferClass = TypeResolver.resolveClass("okio.Buffer");
            BufferedSourceClass = TypeResolver.resolveClass("okio.BufferedSource");
            CharsetClass = TypeResolver.resolveClass("java.nio.charset.Charset");
            JSONObjectClass = TypeResolver.resolveClass("org.json.JSONObject");
            
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
            InterceptorChainRequestMeth = InterceptorChainClass.getMethod("request");
            InterceptorChainProceedMeth = InterceptorChainClass.getMethod("proceed", RequestClass);
            RequestNewBuilderMeth = RequestClass.getMethod("newBuilder");
            RequestBodyMeth = RequestClass.getMethod("body");
            RequestHeaderMeth = RequestClass.getMethod("header", String.class);
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

            // === CONSTRUCTOR RESOLUTION ===
            FormBodyBuilderConst = FormBodyBuilderClass.getConstructor();

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

            Log.d(EntryPoint.TAG, "BaseParametersInterceptor hook installed successfully!");

        } catch (Exception e) {
            Log.e(EntryPoint.TAG, "hookBaseParamsInterc(): [error] " + e);
            e.printStackTrace();
        }
    }
}
