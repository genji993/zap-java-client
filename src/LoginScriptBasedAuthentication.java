/* Created by Carmelo Riolo 21/05/2017 */


import java.util.ArrayList;
import java.util.List;

import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ApiResponseList;
import org.zaproxy.clientapi.core.ApiResponseSet;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;


public class LoginScriptBasedAuthentication {
	
	private static List<String> scripts				= null;
	private static final String scriptname			= "loaded_zest_login_script";
	private static final String logged_in_indicator = "<a href=\"logout.php\">Logout</a>";
	private static 		 String contextId			= null;
	
	
//	private static void listAllEngines(ClientApi clientApi) throws ClientApiException{
//		
//		ApiResponseList enginesList = (ApiResponseList) clientApi.script.listEngines();
//		for(ApiResponse res:enginesList.getItems()){
//			ApiResponseElement elem = (ApiResponseElement) res;
//			
//		}
//		
//	}
	
	private static void loadAllScripts(ClientApi clientApi) throws ClientApiException{
		
		ApiResponseList scriptsList = (ApiResponseList) clientApi.script.listScripts();
		for(ApiResponse res:scriptsList.getItems()){
			ApiResponseSet set = (ApiResponseSet) res;
			scripts.add(set.getValue("name").toString());
//			System.out.println(set.getValue("name"));
		}
		
		
	}
	

	private static String addLoadUser(ClientApi clientApi,String user) throws ClientApiException{
		
		ApiResponseList usersList = (ApiResponseList)clientApi.users.usersList(contextId);

//		 Looking for user existence
		for(ApiResponse resp:usersList.getItems()){
			String str = ((ApiResponseSet)resp).getValue("name").toString();
//			System.out.println(str);
			if(str.equals(user))
				return ((ApiResponseSet)resp).getValue("id").toString();
		}
		
//		 Adding user if does not exists
		ApiResponse resp = clientApi.users.newUser(contextId, user);
//		System.out.println("Added user with id: "+((ApiResponseElement)resp).getValue());
//		clientApi.users.setUserEnabled(contextId, ((ApiResponseElement)resp).getValue(), "true");
		
	
		return ((ApiResponseElement)resp).getValue().toString();
		
	}
	
	public static void listUserConfigInformation(ClientApi clientApi) throws ClientApiException {
//		 Check out which are the config parameters required to set up an user with the currently
//		 set authentication methods
		String contextId = "1";
		ApiResponseList configParamsList = (ApiResponseList) clientApi.users
				.getAuthenticationCredentialsConfigParams(contextId);

		StringBuilder sb = new StringBuilder("Users' config params: ");
		for (ApiResponse r : configParamsList.getItems()) {
			ApiResponseSet set = (ApiResponseSet) r;
			sb.append(set.getValue("name")).append(" (");
			sb.append((set.getValue("mandatory").equals("true") ? "mandatory" : "optional"));
			sb.append("), ");
		}
//		System.out.println(sb.deleteCharAt(sb.length() - 2).toString());
	}


	private static void loadZestScript(ClientApi clientApi) throws ClientApiException{
		
		
		String scriptengine = "Zest : Mozilla Zest";
		String scripttype 	= "authentication";
		String filename 	= "/root/Scrivania/dvwa_login_zest.zst";
		String description 	= "Zest Script loaded via Java API Client for automated security test of DVWA";
		
		clientApi.script.load(scriptname, scripttype, scriptengine, filename, description);
		
		
	}
	
	public static void setLoggedInIndicator(ClientApi clientApi,final String indicator) throws ClientApiException {
//		 Prepare values to set, with the logged in indicator as a regex matching the logout link
		String loggedInIndicator = indicator;

//		 Actually set the logged in indicator
		clientApi.authentication.setLoggedInIndicator(contextId, java.util.regex.Pattern.quote(loggedInIndicator));

//		 Check out the logged in indicator that is set
//		System.out.println("Configured logged in indicator regex: "
//				+ ((ApiResponseElement) clientApi.authentication.getLoggedInIndicator(contextId)).getValue());
	}

	
	private static void setScriptBasedAuthentication(ClientApi clientApi) throws ClientApiException{
		// Setup the authentication method
		StringBuilder scriptBasedConfig = new StringBuilder();
		scriptBasedConfig.append("scriptName=").append(scriptname);
		
		
//		System.out.println("Setting script based authentication configuration as: "
//				+ scriptBasedConfig.toString());

		clientApi.authentication.setAuthenticationMethod(contextId, "scriptBasedAuthentication",
				scriptBasedConfig.toString());

//		 Check if everything is set up ok
//		System.out.println("Authentication config: " + clientApi.authentication.getAuthenticationMethod(contextId).toString(0));
	}
	
	
	/*
	 * 
	 * Returns the id of the user authenticated successfully otherwise null
	 * 
	 */
	public static String authenticate(ClientApi clientApi,String user,String id){
	
		contextId		= id;
		String userId	= null;
		
		if(scripts==null)
			scripts = new ArrayList<String>();
		
		
		
		
		try{
			
			/* Debug Information(s) */
//			listAllEngines(clientApi);
			loadAllScripts(clientApi);	
			
			/* Load Script Into ZAP */
			if(!scripts.contains(scriptname))
				loadZestScript(clientApi);
	
			
			/* Set Authentication Mtehod as scriptBasedAuthentication*/
			setScriptBasedAuthentication(clientApi);
			
			setLoggedInIndicator(clientApi,logged_in_indicator);
			
			/* If the user already exists the identifier is returned otherwise the user is created and the identifier is returned */
			userId = addLoadUser(clientApi,user);
			listUserConfigInformation(clientApi);
			
			return userId;
			
		}catch(ClientApiException ex){
			ex.printStackTrace();
			return null;
		}
		
	}


}
