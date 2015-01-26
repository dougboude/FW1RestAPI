component output="false" displayname="" hint="controllers requiring security extend me"
{
	authService = createObject("cfc","model.services.authService").init(application.dsn,application.expectedHeaders);
	
	public void function before(){
		rc.authResults = authService.authenticate(rc);
		
		if(NOT rc.authResults.authSuccess){//we had a failure in our authentication process!
			var retval = authService.makePayload(debug={diedon="died in basecontroller attempting to authenticate this request"},data="",authResults=rc.authResults,success=false,error="an error was encountered. Authentication failed, or an incorrect request method was used.");

			//set our return header so the caller knows something's up
			getPageContext().getResponse().setHeader("success", false);
			
			try{//need to abort any queued controllers
				variables.fw.abortController();
			}catch(any e){
			}
			variables.fw.renderData("json",retval,401);
		}
	}
}