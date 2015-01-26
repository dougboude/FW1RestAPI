component output="false" displayname="" accessors="true" extends="baseSecurityController"  {

	public function init(required any fw){
		variables.fw = fw;
		return this;
	}
	
	public void function login (required any rc){
		//performing some cool authentication stuff here...
		
		var mysuccess = true;
		var myerror = (!mysuccess)?"I could not log you in!":"";
		//if we had encountered an error, our function should probably not be returning any data
		var mydata = (!mysuccess)?{}:duplicate(rc.authResults.data);
		mydata.username = rc.username;
		mydata.password = rc.password;
		var debug = (!mysuccess)?{detail="I am more detail on why login failed."}:{};
		var payload = authService.makePayload(data=mydata,authResults=rc.authResults,success=mysuccess,error=myerror,debug=debug);
		
		//set success header appropriately
		getPageContext().getResponse().setHeader("success", (!payload.createPayloadSuccess || !mysuccess)?false:true);
		
		var retcode = (mysuccess)?200:401;
		variables.fw.renderData("json",payload,retcode);
	}
}