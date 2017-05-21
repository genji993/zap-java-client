/* Created by Carmelo Riolo 21/05/2017 */
/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The Zed Attack Proxy Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.text.SimpleDateFormat;
import java.util.Date;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

public class AutomateZapOnDVWA {

	private static ClientApi api;
	private static final String ZAP_ADDRESS = "localhost";
    private static final int ZAP_PORT = 8090;
    private static final String ZAP_API_KEY = null; // Change this if you have set the apikey in ZAP via Options / API
    private static final String TARGET = "http://192.168.1.9:8888/dvwa";
    private static final String REPORT_PREFIX = "dvwa_low_level_security_";
    private static final String DEFAULT_CONTEXT_ID = "1";

    
    private static void Spider(String entryPoint, String userId) throws ClientApiException, InterruptedException, UnsupportedEncodingException{
    	 
    	 System.out.println("Spidering from: " + entryPoint);
         ApiResponse resp = api.spider.scanAsUser(DEFAULT_CONTEXT_ID, userId, TARGET, "0", "True", "False");         
         String scanid;
         int progress;

         // The scan now returns a scan id to support concurrent scanning
         scanid = ((ApiResponseElement) resp).getValue();

         // Poll the status until it completes
         
    	 while (true) {
             Thread.sleep(1000);
             progress = Integer.parseInt(((ApiResponseElement) api.spider.status(scanid)).getValue());
             System.out.println("Spider progress : " + progress + "%");
             if (progress >= 100) {
                 break;
             }
             
             
         }
        
    	 System.out.println("Spidering complete...");
         
         
         
         
    }
    
    private static void ActiveScan(String target,String userId) throws ClientApiException, InterruptedException{
    	System.out.println("Active scan : " + target);
    	ApiResponse resp = api.ascan.scanAsUser(TARGET, DEFAULT_CONTEXT_ID, userId, "true", "Politica predefinita", null, null);
    	String scanid;
        int progress;

        
        // The scan now returns a scan id to support concurrent scanning
        scanid = ((ApiResponseElement) resp).getValue();

        // Poll the status until it completes
        while (true) {
            Thread.sleep(5000);
            progress = Integer.parseInt(((ApiResponseElement) api.ascan.status(scanid)).getValue());
            System.out.println("Progress : " + progress + "%");
            if (progress >= 100) {
                break;
            }
        }
        System.out.println("Active Scan complete");
    }
    
    public static void main(String[] args) {
    	
    	String username = "user";
    	String userId	= null;
    	api = new ClientApi(ZAP_ADDRESS, ZAP_PORT, ZAP_API_KEY);
    	
    	try {
    		
    		// Adding DVWA in Zap Context
    		api.context.includeInContext("Default Context", TARGET+".*");
        	
    		
    		// Setting authentication as scriptBased
    		userId = LoginScriptBasedAuthentication.authenticate(api,username,DEFAULT_CONTEXT_ID);
    		
    		if(userId!=null){
    		    
    			// Start spidering the target
    			Spider(TARGET,userId);

                // Give the passive scanner a chance to complete
                Thread.sleep(2000);

                ActiveScan(TARGET,userId);


    			System.out.println("Making report...");
                // Creating file with report
                PrintWriter writer = new PrintWriter(REPORT_PREFIX+getCurrentTimestamp()+".xml", "UTF-8");
                writer.println(new String(api.core.xmlreport()));
                writer.close();
            
                
    		}
    		
            
            
        } catch (Exception e) {
            System.out.println("Exception : " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static String getCurrentTimestamp(){
    	return new SimpleDateFormat("yyyy_MM_dd_HH.mm.ss").format(new Date()).toString();
    }

}