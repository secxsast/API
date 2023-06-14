/* 
 * Copyright (c) 2017 RSA, a Dell Technologies business. All rights reserved.
 */
package com.rsa.authmgr.mfarest;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.util.Base64;
import org.apache.commons.codec.binary.Hex;

import com.rsa.securid.authentication.ApiClient;
import com.rsa.securid.authentication.ApiException;
import com.rsa.securid.authentication.auth.ApiKeyAuth;
import com.rsa.securid.authentication.openapi.Cancel;
import com.rsa.securid.authentication.openapi.CheckStatus;
import com.rsa.securid.authentication.openapi.Initialize;
import com.rsa.securid.authentication.openapi.Verify;
import com.squareup.okhttp.RequestBody;

import okio.Buffer;

/**
 * This provides an interface to calculate and set the API key value for the request.
 * 
 * NOTE:
 *  THIS SAMPLE SOURCE CODE IMPLEMENTATION AND RELATED CONTENT AND DOCUMENTATION IS PROVIDED "AS IS" AND
 *  IS FOR REFERENCE PURPOSES ONLY.  RSA AND ITS LICENSORS AND SUPPLIERS MAKE NO EXPRESS OR IMPLIED
 *  REPRESENTATIONS OR WARRANTIES AS TO ANY MATTER WHATSOEVER, INCLUDING, WITHOUT LIMITATION, WARRANTIES
 *  AS TO PERFORMANCE, TITLE, NON-INFRINGEMENT, MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 *  IN NO EVENT WILL RSA OR ITS LICENSORS OR SUPPLIERS BE LIABLE FOR DIRECT DAMAGES OR INCIDENTAL,
 *  CONSEQUENTIAL, SPECIAL OR INDIRECT DAMAGES RELATING TO THE SAMPLE IMPLEMENTATION AND/OR ITS USE BY
 *  USER, EVEN IF RSA OR ITS LICENSORS OR SUPPLIERS HAVE BEEN ADVISED OF THE POSSIBILITY OF THE SAME.
 *  THE SAMPLE SOURCE CODE IMPLEMENTATION MAY CONTAIN DEFECTS, FAULTS, ERRORS AND OMISSIONS. USER IS
 *  SOLELY RESPONSIBLE FOR THE PROTECTION AND BACK-UP OF ANY USER DATA, SOFTWARE OR OTHER MATERIALS USED
 *  IN CONNECTION WITH THE SAMPLE SOURCE CODE IMPLEMENTATION, AND FOR ANY SOFTWARE, CONTENT OR SERVICE
 *  GENERATED FROM OR IN CONNECTION WITH SUCH SAMPLE SOURCE CODE IMPLEMENTATION.
 */
public class SecurityUtils {
    
    /**
     * Public enum for the types of keys supported:
     *   KEY  - Static key value provided.
     *   HMAC - Dynamically generated request-based HMAC. 
     */
    public enum KeyType { KEY, HMAC };

	private static final String HMAC_SIGNATURE_ALGORITHM = "HmacSHA256";

	private static final String HASHING_ALGORITHM = "SHA-512";
	
	private static final DateFormat DATE_FORMATTER = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssX");

    /*
     * Derive the REST path based on the request type. Optimally, this data would be available from
     *          the object itself.
     */
    private static String getInterfacePath(String pathPrefix, Object request) {
        if (request instanceof Initialize) {
            return pathPrefix + "/authn/initialize";
        } else if (request instanceof Verify) {
            return pathPrefix + "/authn/verify";
        } else if (request instanceof Cancel) {
            return pathPrefix + "/authn/cancel";
        }  else if (request instanceof CheckStatus) {
            return pathPrefix + "/authn/status";
        }
        return pathPrefix + "/authn/resource";
    }
    
    /*
     * sets the key for a request and a given request type.
     */
    private static RequestBody getRequestBody( ApiClient apiClient, Object serverRequest) {
        RequestBody reqBody = null;
        try {
            reqBody = apiClient.serialize(serverRequest, "application/json");
        } catch (ApiException e) {
            System.err.println("Unable to get RequestBody for request.");
            e.printStackTrace();
        }
        return reqBody;
    }

	/**
	 * This calculates and sets the API key for the request.
	 * 
	 * @param apiClient - the API Client in which the key may be set.
	 * @param securityKeyType - The type of security key required. (KEY or HMAC)
	 * @param request - The request object.
	 * @param pathPrefix - The request path prefix.
	 * @param methodType - The method type (POST/GET)
	 * @param accessID - The access ID
	 * @param accessKey - The Access Key
	 * 
	 * @throws Exception on unexpected interface failure.
	 */
	public static void setApiKey(ApiClient apiClient, KeyType securityKeyType, final Object request, final String pathPrefix,
	                                 final String methodType, final String accessID, final byte[] accessKey)
	                                         throws IOException, NoSuchAlgorithmException, InvalidKeyException {
	    String requestKey = null;
	    switch (securityKeyType) {
            case KEY:
                // This is a simple key value.
                requestKey = new String(accessKey);
                break;
    	    case HMAC:
    	        // Calculates a HMAC for the header by hashing the request body and using the key to generate
    	        //    an HMAC of the method type, content hash, path, date and the Access ID for the API.
    	        RequestBody reqbody = getRequestBody(apiClient, request);
        		// Calculate the hash of the request body.
        		String contentHash = calculateHash(getBodyAsString(reqbody));
        		// Get a date string.
        		String dateString = DATE_FORMATTER.format(new Date());
        		// Build the string that is used in calculating the HMAC.
        		String messageToHMAC = methodType + "\n" + contentHash + "\n" + getInterfacePath(pathPrefix, request) + 
        		                           "\n" + dateString + "\n" + accessID;
        		// Generate a HMAC of the request.
                requestKey = generateHMAC(messageToHMAC, accessKey);  
                // Add the request date used in the HMAC in the HTTP header.
                apiClient.addDefaultHeader("Date", dateString);
                break;
            default:
                break;
	    }
	    if (requestKey != null) {
	        // Add the ID to the request.
            apiClient.addDefaultHeader("X-Access-ID", accessID);
            
            // Get the client API key and set the request key.
            ApiKeyAuth clientKey = (ApiKeyAuth)apiClient.getAuthentication("client-key");
            if (clientKey != null) {
                clientKey.setApiKey(requestKey);
            } else {
                throw new InvalidKeyException("Unable to get ApiKeyAuth 'client-key'");
            }
	    }
		return;
	}
		
	// Gets the request body (JSON) as a String
	private static String getBodyAsString(final RequestBody mRequest) throws IOException {
	    if ((mRequest == null) || mRequest.equals("")) {
	        return new String("");
	    }
	    Buffer buffer = new Buffer();
	    mRequest.writeTo(buffer);
	    return buffer.readUtf8();
	}
		
	// Calculates a Hex encoded string of the string passed.
	private static String calculateHash(String contentToHash) throws NoSuchAlgorithmException {	
		if(contentToHash == null || contentToHash.isEmpty())
			return "";
		MessageDigest md = MessageDigest.getInstance(HASHING_ALGORITHM);
		return new String(Hex.encodeHex(md.digest(contentToHash.getBytes())));
	}

	// Generates a Base-64 encoded string of an HMAC of the String passed using the key passed.
	private static String generateHMAC(String messageToSign, byte[] hmacKey) throws NoSuchAlgorithmException, InvalidKeyException {		
		SecretKeySpec secretKeySpec = new SecretKeySpec(hmacKey, HMAC_SIGNATURE_ALGORITHM);
        Mac mac = Mac.getInstance(HMAC_SIGNATURE_ALGORITHM);
		mac.init(secretKeySpec);
		return new String(Base64.getEncoder().encodeToString(mac.doFinal(messageToSign.getBytes())));
	}
}
