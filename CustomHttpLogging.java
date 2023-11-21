/* 
 * Copyright (c) 2017 RSA, a Dell Technologies business. All rights reserved.
 */
package com.rsa.authmgr.mfarest;

import java.io.IOException;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.squareup.okhttp.Interceptor;
import com.squareup.okhttp.Response;
import com.squareup.okhttp.logging.HttpLoggingInterceptor;
import com.squareup.okhttp.logging.HttpLoggingInterceptor.Level;
import com.squareup.okhttp.logging.HttpLoggingInterceptor.Logger;

/**************************************************************************************
 * Custom logging intercepter to "pretty-print" JSON data.test 
 * 
 * Optional. This is not required for REST interface usage.
 * 
 *  NOTE:
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
public final class CustomHttpLogging implements Interceptor,Logger {
    
	private HttpLoggingInterceptor loggingInterceptor = null;
	
	/*
	 * Void constructor.
	 */
	public CustomHttpLogging() {
		loggingInterceptor = new HttpLoggingInterceptor(this).setLevel(Level.BODY);
	}
	
	/*
	 * Intercept a log string message. This checks if the line starts with what appears to be a JSON
	 *     string. If the line starts with a JSON string, it formats it with a "pretty-print" interface.
	 *     Otherwise, the string is simply sent to System.out.
	 *     
	 * @see com.squareup.okhttp.logging.HttpLoggingInterceptor.Logger#log(java.lang.String)
	 */
    @Override
    public void log(String message) {
        if ((!message.startsWith("{")) &&    // handle JSON or JSON array
            (!message.startsWith("["))) {
            System.out.println(message);
            return;
        }
        try {
        	System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(new JsonParser().parse(message)));
        } catch (JsonSyntaxException m) {
        	System.out.println("JSON Exception: "+m.getLocalizedMessage()+ ": Message="+ message);
        }
    }
    
    /*
     * Pass the chain to our internal logging intercepter. sa
     * 
     * @see com.squareup.okhttp.Interceptor#intercept(com.squareup.okhttp.Interceptor.Chain)
     */
	@Override
	public Response intercept(Chain chain) throws IOException {
		return loggingInterceptor.intercept(chain);
	}
}


