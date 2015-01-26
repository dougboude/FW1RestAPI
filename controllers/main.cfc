component output="false" displayname="" accessors="true"  {

	authService = createObject("cfc","model.services.authService").init(application.dsn,application.expectedHeaders);
	
	public function init(required any fw){
		variables.fw = fw;
		return this;
	}

	public void function default (required any rc) {
		
	}
	
	public void function getTest (required any rc){
		//if this request is from an api consumer
		if(structKeyExists(getHttpRequestData().headers, "pubkey")){
			var retval = {};
			var debug = {message="",detail="",diedon=""};
			retval = authService.makePayload(data={msg: "get Test success"},authResults=(structkeyexists(rc,"authResults"))?rc.authResults:{},debug=debug,success=true,psuccess="true",error="");
		
			//set our return header so the caller knows something's up
			getPageContext().getResponse().setHeader("success", true);

			variables.fw.renderData("json",retval);
		}
	}
	
	public void function error (required any rc){
		//if this failed request is from an api consumer
		if(structKeyExists(getHttpRequestData().headers, "pubkey")){
			var retval = {};
			var debug = {message="",detail="",diedon=""};
			
			if(structKeyExists(request, "exception") && structKeyExists(getHttpRequestData().headers, "debug") && getHTTPRequestData().headers.debug){
				debug.message = request.exception.message;
				debug.detail = request.exception.detail;
				debug.rootcause = request.exception.rootcause;
				debug.diedon = "this debug struct created while trapping a site error.";
			}
			
			retval = authService.makePayload(data={},authResults=(structkeyexists(rc,"authResults"))?rc.authResults:{},debug=debug,success=false,psuccess="false",error="an error was encountered. Possible causes: bad URL, or incorrect request method. You requested #cgi.request_url#. If the URL is correct, check the request method used. If debugging is enabled, see debug.message for more info.");
			
			//set our return header so the caller knows something's up
			getPageContext().getResponse().setHeader("success", false);

			variables.fw.renderData("json",retval,401);

		} else {
			//we'll let the error view be used.
		}	
		
	}
}