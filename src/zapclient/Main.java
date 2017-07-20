package zapclient;

import java.io.UnsupportedEncodingException;

import org.zaproxy.clientapi.core.ClientApiException;

public class Main {

	public static void main(String[] args){

		// Info ZAP
		String zap_address = "localhost";
		int zap_port = 8090;
		String zap_api_key = "";
		
		// Dominio
		String site_name = "192.168.1.27";
		
		// Percorso all'interno del dominio
		String path = "dvwa";
		
		// Nome Contesto
		String contextName = "dvwaContext";
		
		// Percorso allo script di Autenticazione
		String scriptPath  = "/root/workspace/zap-java-client/auth_dvwa.zst";
		
		// Cookie di Sessione
		String sessionToken = "PHPSESSID";
		
		// Pagine da escludere dal crawling
		String login_file = "login.php";
		String logout_file = "logout.php";
		String setup_file = "setup.php";
		String logoutURL = "http://"+site_name+"/"+path+"/"+logout_file;
		String setupURL = "http://"+site_name+"/"+path+"/"+setup_file;
		// LoginURL, Username e Password per lo script di Autenticazione ZEST
		String loginURL = "http://"+site_name+"/"+path+"/"+login_file;
		String username = "admin";
		String password = "password";
		
		
		
		
		
		
		try {
			
			ZapJavaClient client = new ZapJavaClient(zap_address, 
					zap_port, 
					zap_api_key, 
					site_name, 
					path,
					contextName,
					scriptPath,
					null, 
					sessionToken,
					username,
					password, 
					loginURL);
			

			client.ExcludeFromSpider(loginURL);
			client.ExcludeFromSpider(logoutURL);
			client.ExcludeFromSpider(setupURL);
			
			// Crawling
			client.Spider();
			
			// Ajax Spidering
			client.AjaxSpider();
			
			// Active Scanning
			client.ActiveScan();
			
		} catch (ClientApiException | UnsupportedEncodingException | InterruptedException e) {
			e.printStackTrace();
		}
		
		
	}
	
}
