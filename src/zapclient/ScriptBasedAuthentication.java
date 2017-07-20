package zapclient;
/*
* ScriptBasedAuthentication.java
*
* Tale classe espone tutti i metodi necessari per realizzare
* un autenticazione basata su script.
* Alla classe chiamante e affidata la responsabilita di passare il percorso
* dello script da caricare.
* Se non e gia caricato all'interno di ZAP, questo verra
* automaticamente caricato.
*
* Creato da Carmelo Riolo 21/05/2017
*/
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ApiResponseList;
import org.zaproxy.clientapi.core.ApiResponseSet;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;


public class ScriptBasedAuthentication {

	private static void loadAllScripts(ArrayList<String> scripts, ClientApi clientApi) throws ClientApiException{
		ApiResponseList scriptsList = (ApiResponseList) clientApi.script.listScripts();
		for(ApiResponse res:scriptsList.getItems()){
			ApiResponseSet set = (ApiResponseSet) res;
			scripts.add(set.getValue("name").toString());
		}
	}


	public static void listUserConfigInformation(ClientApi clientApi) throws ClientApiException {
		String contextId = "1";
		ApiResponseList configParamsList = (ApiResponseList) clientApi.users.getAuthenticationCredentialsConfigParams(contextId);
		StringBuilder sb = new StringBuilder("Users' config params: ");
		for (ApiResponse r : configParamsList.getItems()) {
			ApiResponseSet set = (ApiResponseSet) r;
			sb.append(set.getValue("name")).append(" (");
			sb.append((set.getValue("mandatory").equals("true") ? "mandatory" :"optional"));
			sb.append("), ");
		}
	}

	private static void loadZestScript(ClientApi clientApi, String script_name, String script_path) throws ClientApiException{
		String scriptengine = "Zest : Mozilla Zest";
		String scripttype = "authentication";
		String description = "Zest Script loaded via Java API Client for automated security test of DVWA";
		clientApi.script.load(script_name, scripttype, scriptengine, script_path, description);
			clientApi.script.enable(script_name);
	}

	public static void setLoggedInIndicator(ClientApi clientApi, String contextId, final String indicator) throws ClientApiException {
		String loggedInIndicator = indicator;
		clientApi.authentication.setLoggedInIndicator(contextId, java.util.regex.Pattern.quote(loggedInIndicator));
	}

	private static void setScriptBasedAuthentication(ClientApi clientApi, String contextId, String script_name, String loginURL) throws ClientApiException{
		StringBuilder scriptBasedConfig = new StringBuilder();
		scriptBasedConfig.append("scriptName=").append(script_name).append("&LoginURL=").append(loginURL);
		clientApi.authentication.setAuthenticationMethod(contextId, "scriptBasedAuthentication", scriptBasedConfig.toString());
	}

	public static void load(ClientApi clientApi, String contextId, String script_path, String loginURL) throws ClientApiException{

		ArrayList<String> scripts = new ArrayList<String>();
		String script_name = "auth_script";
		
		/* Carico gli script già presenti */
		loadAllScripts(scripts, clientApi);
		
		/* Carico Script Autenticazione in ZAP */
		if(!scripts.contains(script_name))
			loadZestScript(clientApi, script_name, script_path);

		/* Imposto metodo di autenticazione basato su script */
		setScriptBasedAuthentication(clientApi, contextId, script_name, loginURL);

	
	}
}
