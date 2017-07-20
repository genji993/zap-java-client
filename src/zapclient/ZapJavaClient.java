package zapclient;
/*
 * ZapJavaClient.java
 * Tale script esegue Spider e Active Scan
 *
 * Creato da Carmelo Riolo 21/05/2017
 */
import java.io.UnsupportedEncodingException;
import java.util.List;

import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ApiResponseList;
import org.zaproxy.clientapi.core.ApiResponseSet;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

public class ZapJavaClient {

	private String 	ZapAddress;
	private int		ZapPort;
	private String 	ZapApiKey; // If enabled
	private String 	SiteName;
	private String 	Path;
	private String 	ContextName; 
	private String 	ScriptPath;
	private String 	ScanPolicy;
	private String	SessionToken;
	private String	SiteURL;
	private String	LoginURL;
	private String	Username;
	private String	Password;

	
	private ClientApi
					api;
	private String 	contextId;
	private String	sessionTokenValue;
	private String	user = "javaclient";
	private String	userId;

	private static final String DEFAULT_CONTEXT_NAME = "zapjavaclient";
	private static final String DEFAULT_SCRIPT_NAME = "zestscript";
	
	// TODO get Default Context Name From zap
	
	
	
	/* Full Constructor */
	public ZapJavaClient(String zapAddress, int zapPort, String zapApiKey, String siteName, String path,
			String contextName, String scriptPath, String scanPolicy, String sessionToken, String username, String password, String loginURL) throws ClientApiException {
	
		ZapAddress = zapAddress;
		ZapPort = zapPort;
		ZapApiKey = zapApiKey;
		SiteName = siteName;
		Path = path;
		ContextName = contextName;
		ScriptPath = scriptPath;
		SessionToken = sessionToken;
		SiteURL = "http://"+SiteName+"/"+Path;
		LoginURL = loginURL;
		Username = username;
		Password = password;
		
		api = new ClientApi(ZapAddress, ZapPort, ZapApiKey);
		
		if(scanPolicy==null){
			
			ApiResponse resp;
			resp = api.ascan.scanPolicyNames();
			ApiResponseList list = (ApiResponseList)resp;
			ScanPolicy = list.getItems().get(0).toString();
			
		}else
			ScanPolicy = scanPolicy;
		
		ApiResponse response;
		
		// Creo un nuovo contesto se non esiste
		if(!api.context.contextList().toString().contains(ContextName)){
			api.context.newContext(ContextName);
			// Aggiungo l'applicazione Path al Contesto
			response = api.context.includeInContext(ContextName, SiteURL+".*");
		}
		
		response = api.context.context(ContextName);
		ApiResponseSet  contextInfo = (ApiResponseSet) response;
		contextId = contextInfo.getValue("id").toString();


		
		

		// Imposto Autenticazione basata su script
		ScriptBasedAuthentication.load(api, contextId, ScriptPath, LoginURL);
		
		addUserIfNotExists();

		
	}

	
	private void addUserIfNotExists() throws ClientApiException{
		
		
		ApiResponseList usersList = (ApiResponseList)api.users.usersList(contextId);
		
		// Controllo esistenza utente
		for(ApiResponse resp:usersList.getItems()){
			String str = ((ApiResponseSet)resp).getValue("name").toString();
			if(str.equals(user)){
				userId = ((ApiResponseSet)resp).getValue("id").toString(); 
				return;
			}
		
		}
		//Aggiungo utente se non esiste
		ApiResponse resp = api.users.newUser(contextId, user);
		userId = ((ApiResponseElement)resp).getValue().toString();
		StringBuilder userCredentials = new StringBuilder();
		userCredentials.append("Username=").append(Username).append("&Password=").append(Password);
		api.users.setAuthenticationCredentials(contextId, userId, userCredentials.toString());
		api.users.setUserEnabled(contextId, userId, "True");
		

	}
	private void FlagSessionToken() throws ClientApiException, InterruptedException{
		
		if(SessionToken==null)
			throw new ClientApiException("Session Token is Null");
		
		/* Get Sessions */
		boolean flag = false;
		ApiResponse resp = api.params.params(SiteName);
		ApiResponseList list = (ApiResponseList)resp;
		ApiResponse parameter = list.getItems().get(0);
		List<ApiResponse> arlist = ((ApiResponseList)parameter).getItems();
		for(int i=0;i<arlist.size();i++){
		
			Object o = arlist.get(i);
			if(o instanceof ApiResponseSet && !flag){
				ApiResponseSet site = (ApiResponseSet)arlist.get(i);
				for(ApiResponse res:site.getValues()){
					if(res.getName().equals("name")){
						ApiResponseElement name = (ApiResponseElement)res;
						if(name.getValue().equals(SessionToken)){
							flag = true;
						}
							
					}
				}
			}else if(o instanceof ApiResponseList){
				if(flag){
					ApiResponseList site = (ApiResponseList)arlist.get(i);
					ApiResponseElement el = (ApiResponseElement)site.getItems().get(site.getItems().size()-1);
					sessionTokenValue = el.getValue();
					break;
				}
			}
		}
		//System.out.println("Cookie: "+SessionToken+": "+sessionTokenValue+";");
		api.httpSessions.createEmptySession(SiteName, "javasession");
		api.httpSessions.setSessionTokenValue(SiteName, "javasession", SessionToken, sessionTokenValue);
		Thread.sleep(3000);
		//api.httpSessions.setActiveSession(SiteName, "dvwa");
	}
	public void Spider() throws ClientApiException, InterruptedException, UnsupportedEncodingException{

		System.out.println("Starting Spider...");
		ApiResponse resp = api.spider.scanAsUser(contextId, userId, SiteURL, "0", "True", "False");
		String scanid;
		int progress;
		scanid = ((ApiResponseElement) resp).getValue();
		while (true) {
			Thread.sleep(1000);
			progress = Integer.parseInt(((ApiResponseElement)api.spider.status(scanid)).getValue());
			//System.out.println("Spider progress : " + progress + "%");
			if (progress >= 100)
			break;
		}
		System.out.println("Spider Ended...");
	}
	public void AjaxSpider() throws ClientApiException, InterruptedException{
		
		if(SessionToken!=null)
			FlagSessionToken();
		
		System.out.println("Starting Ajax Spider");
		api.ajaxSpider.scanAsUser(ContextName, user, SiteURL+"/index.php", "False");
		ApiResponse res =(ApiResponse) api.ajaxSpider.status();
		ApiResponseElement elem = (ApiResponseElement) res;
		
		
		while(true){
			res = (ApiResponse) api.ajaxSpider.status();
			elem = (ApiResponseElement) res;
			if(elem.getValue().equals("running"))
				break;
			Thread.sleep(1000);
		}
		while(true){
			res = (ApiResponse) api.ajaxSpider.status();
			elem = (ApiResponseElement) res;
			if(elem.getValue().equals("stopped"))
				break;
			Thread.sleep(1000);
		}
		System.out.println("Ajax Spider Ended");
		Thread.sleep(1000);
	}
	public void ActiveScan() throws ClientApiException, InterruptedException{

		ApiResponse resp;

		System.out.println("Active scan Started");

		resp = api.ascan.scan(SiteURL, contextId, "True", ScanPolicy, null, null);

		String scanid;
		int progress;
		scanid = ((ApiResponseElement) resp).getValue();
		while (true) {
			Thread.sleep(5000);
			progress = Integer.parseInt(((ApiResponseElement)api.ascan.status(scanid)).getValue());
			//System.out.println("Progress : " + progress + "%");
			if (progress >= 100)
			break;
		}
		System.out.println("Active scan Ended");
	}
	public void ExcludeFromSpider(String url) throws ClientApiException{
		api.spider.excludeFromScan(url+".*");
	}
	public void ExcludeFromActiveScan(String url) throws ClientApiException{
		api.ascan.excludeFromScan(url+".*");
	}
	public void ExcludeFromAll(String url) throws ClientApiException{
		ExcludeFromSpider(url);
		ExcludeFromActiveScan(url);
	}
	
	
	
}
