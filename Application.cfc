component   extends="framework.one" {
	this.Name = "RodeoBayAPI1";
	this.SessionManagement = true;
	
	//this app has no session management
	variables.framework = {
		home = "main.default"
		//,defaultSection = "main"
		//,defaultItem = "default"
		,error = 'main.error'
		,generateSES = true
		,SESOmitIndex = false
		,usingSubSystems = false
		,trace=true
		,routes = [
			{ "$GET/users/$" = "/users/list" },
			{ "$GET/users/:id/$" = "/users/get/id/:id" },
			{ "$POST/users/$" = "/users/create" },
			{ "$DELETE/users/:id/$" = "/users/delete/id/:id" },
			{ "$POST/users/login/$" = "/users/login" },
			{ "$GET/getTest/$" = "/main/getTest" },
			{ "$POST/authenticate/:username/:password/$" = "/security/login/username/:username/password/:password" },
			{ "$POST/authenticate/:username/$" = "/security/login/username/:username/password/ " },
			{ "$POST/authenticate/$" = "/security/login/username/ /password/ " }
			]
	};
	
	public boolean function onApplicationStart(){
		application.dsn = "rodeobay";
		application.failedAuthAction="main.authfail";
		application.expectedHeaders = "handle,pubkey,authtoken";
		application.secretkey = "derpaderp";
		return true;
	}
}