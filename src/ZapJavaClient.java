package zapclient;
/*
 * ZapJavaClient.java
 * Tale script esegue Spider e Active Scan
 *
 * Creato da Carmelo Riolo 21/05/2017
 */
import java.io.UnsupportedEncodingException;

import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ApiResponseList;
import org.zaproxy.clientapi.core.ApiResponseSet;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

public class ZapJavaClient {

	private static ClientApi 	api;
	private static final String ZAP_ADDRESS = "localhost";
	private static final int	ZAP_PORT = 8090;
	private static final String ZAP_API_KEY = "";
	private static final String SITE_NAME = "localhost:8888";
	private static final String TARGET = "http://"+SITE_NAME+"/dvwa/";
	private static final String DEFAULT_CONTEXT_NAME = "dvwa"; //Target Application Here
	private static final String SCRIPT_PATH = "/Users/carmelor/Documents/workspace/ZapJavaClient/src/zapclient/zest_auth_script.zst";
	private static String 		default_policy = null;
	private static String 		contextId;


	private static void Spider(String entryPoint,String userId) throws ClientApiException, InterruptedException, UnsupportedEncodingException{

		System.out.println("Excluding logout.php from Spidering");
		api.spider.excludeFromScan("http://localhost:8888/dvwa/logout.php.*");
		System.out.println("Spidering from: " + entryPoint);
		//ApiResponse resp = api.spider.scan(TARGET, "0", "True", DEFAULT_CONTEXT_NAME, "False");
		ApiResponse resp = api.spider.scanAsUser(contextId, userId, "http://localhost:8888/dvwa/dvwa/", "0", "True", "False");
		String scanid;
		int progress;
		scanid = ((ApiResponseElement) resp).getValue();
		while (true) {
			Thread.sleep(1000);
			progress = Integer.parseInt(((ApiResponseElement)api.spider.status(scanid)).getValue());
			System.out.println("Spider progress : " + progress + "%");
			if (progress >= 100)
			break;
		}
		System.out.println("Spidering complete...");
	}

	private static void ActiveScan(String target) throws ClientApiException, InterruptedException{

		ApiResponse resp;

		System.out.println("Excluding logout.php from Scanning");
		api.ascan.excludeFromScan("http://localhost:8888/dvwa/logout.php.*");
		System.out.println("Active scan : " + target);

		if(default_policy==null){
			resp = api.ascan.scanPolicyNames();
			ApiResponseList list = (ApiResponseList)resp;
			ApiResponseElement elem = (ApiResponseElement)list.getItems().get(0);
			default_policy = list.getItems().get(0).toString();
		}

		resp = api.ascan.scan(TARGET, contextId, "True", default_policy, null, null);

		String scanid;
		int progress;
		scanid = ((ApiResponseElement) resp).getValue();
		while (true) {
			Thread.sleep(5000);
			progress = Integer.parseInt(((ApiResponseElement)api.ascan.status(scanid)).getValue());
			System.out.println("Progress : " + progress + "%");
			if (progress >= 100)
			break;
		}
	}

	public static void main(String[] args) {
		String result = "null";
		api = new ClientApi(ZAP_ADDRESS, ZAP_PORT, ZAP_API_KEY);
		try {

			// Creo un nuovo contesto se non esiste
			if(!api.context.contextList().toString().contains(DEFAULT_CONTEXT_NAME))
				api.context.newContext(DEFAULT_CONTEXT_NAME);

			ApiResponse response = api.context.context(DEFAULT_CONTEXT_NAME);
			ApiResponseSet  contextInfo = (ApiResponseSet) response;
			contextId = contextInfo.getValue("id").toString();


			// Aggiungo l'applicazione target al Contesto
			response = api.context.includeInContext(DEFAULT_CONTEXT_NAME, TARGET+".*");
			System.out.println(response.getName());

			// Imposto Autenticazione basata su script
			result = ScriptBasedAuthentication.authenticate(api, contextId, SCRIPT_PATH);


			if(result!=null){
				final String userId = result;
				Thread spiderThread = new Thread(() -> {
					try {
						Spider(TARGET,userId);
					} catch (UnsupportedEncodingException | ClientApiException | InterruptedException e) {

						e.printStackTrace();
					}
				});

				spiderThread.run();
				spiderThread.join();

				//Thread ajaxSpiderThread

				ActiveScan(TARGET);
			}
		} catch (Exception e) {
			System.out.println("Exception : " + e.getMessage());
			e.printStackTrace();
		}
	}
}
