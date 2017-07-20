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
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ApiResponseList;
import org.zaproxy.clientapi.core.ApiResponseSet;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;


public class ScriptBasedAuthentication {
	private static List<String> scripts = null;
	private static final String scriptname = "auth_dvwa";
	private static final String logged_in_indicator = "<a href=\"logout.php\">Logout</a>";
	private static String contextId = null;
	private static String userId;



	private static void loadAllScripts(ClientApi clientApi) throws ClientApiException{
		ApiResponseList scriptsList = (ApiResponseList) clientApi.script.listScripts();
		for(ApiResponse res:scriptsList.getItems()){
			ApiResponseSet set = (ApiResponseSet) res;
			scripts.add(set.getValue("name").toString());
		}
	}

	private static String addLoadUser(ClientApi clientApi,String user) throws ClientApiException{
		ApiResponseList usersList = (ApiResponseList)clientApi.users.usersList(contextId);
		// Controllo esistenza utente
		for(ApiResponse resp:usersList.getItems()){
			String str = ((ApiResponseSet)resp).getValue("name").toString();
			if(str.equals(user)){
				userId = ((ApiResponseSet)resp).getValue("id").toString();
				return userId;
			}
		}
		//Aggiungo utente se non esiste
		ApiResponse resp = clientApi.users.newUser(contextId, user);
		userId = ((ApiResponseElement)resp).getValue().toString();
		StringBuilder userCredentials = new StringBuilder();
		userCredentials.append("Username=").append("admin").append("&Password=").append("password");
		clientApi.users.setAuthenticationCredentials(contextId, userId, userCredentials.toString());
		clientApi.users.setUserEnabled(contextId, userId, "True");
		return userId;

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

	private static void loadZestScript(ClientApi clientApi, String filename) throws ClientApiException{
		String scriptengine = "Zest : Mozilla Zest";
		String scripttype = "authentication";
		String description = "Zest Script loaded via Java API Client for automated security test of DVWA";
		clientApi.script.load(scriptname, scripttype, scriptengine, filename, description);
			clientApi.script.enable(scriptname);
	}

	public static void setLoggedInIndicator(ClientApi clientApi,final String indicator) throws ClientApiException {
		String loggedInIndicator = indicator;
		clientApi.authentication.setLoggedInIndicator(contextId,
		java.util.regex.Pattern.quote(loggedInIndicator));
	}

	private static void setScriptBasedAuthentication(ClientApi clientApi) throws ClientApiException{
		StringBuilder scriptBasedConfig = new StringBuilder();
		scriptBasedConfig.append("scriptName=").append(scriptname).append("&LoginURL=").append("http://localhost:8888/dvwa/login.php");
		clientApi.authentication.setAuthenticationMethod(contextId, "scriptBasedAuthentication", scriptBasedConfig.toString());
	}

	// Se l'autenticazione e andata a buon fine viene ritornato l'id utente
	public static String authenticate(ClientApi clientApi, String id, String zest_path){

		contextId = id;

		if(scripts==null)
			scripts = new ArrayList<String>();
		try{



			/* Carico gli script gia presenti */
			loadAllScripts(clientApi);
			/* Carico Script Autenticazione in ZAP */
			if(!scripts.contains(scriptname))
				loadZestScript(clientApi,zest_path);

			/* Imposto metodo di autenticazione basato su script */
			setScriptBasedAuthentication(clientApi);

			/* aggiungo utente */
			addLoadUser(clientApi, "user");

			/* Imposto Regex per identificare le pagine autenticate */
			setLoggedInIndicator(clientApi,logged_in_indicator);



			return userId;
		}catch(ClientApiException ex){
			ex.printStackTrace();
			return null;
		}
	}
}
