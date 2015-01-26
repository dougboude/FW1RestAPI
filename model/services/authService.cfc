component output="false" displayname=""
{
	
	public function init(required string dsn,required string expectedHeaders){
		variables.dsn = arguments.dsn;
		variables.expectedHeaders = arguments.expectedHeaders;
		return this;
	}
	
	public struct function authenticate() {// our API's security checkpoint! Nothing passed in, because everything we need is part of the request headers and body
		var proceed = true;
		var qryCreds = "";
		var requestBody = "";
		var thisURL = GetPageContext().GetRequest().GetRequestUrl().toString();
		var thisHMAC = "";
		var authResults = {data="",authSuccess=""};
		
		//if the user passed us a 'debug' header with a value of true, we'll collect extra info to send back
		var debug = (structkeyexists(getHTTPRequestData().headers,"debug") AND getHTTPRequestData().headers.debug IS true)?true:false;
		
		if(debug){authResults.debug={};}
		
		//first, have we received the headers we're expecting? We need 'handle','pubkey', and 'authtoken'
		proceed = headersPresent(headersin = getHTTPRequestData().headers,headersList=expectedHeaders);
		
		//headers present. Retrieve this caller's other credentials
		if(proceed){
			try{
				qryCreds = getCreds(getHTTPRequestData().headers.handle,getHTTPRequestData().headers.pubkey);
			} catch (any e){
				proceed = false;
				if(debug){
					authResults.debug.diedOn = "attempting to query for creds. error: #e.Message#";
				}
			}	
			if(proceed){//query executed. let's see what we retrieved
				if(qryCreds.recordcount neq 1){
					proceed = false;
					if(debug){
						authResults.debug.diedOn = "we retrieved #qryCreds.recordcount# rows when looking up creds. Did you provide the correct values?";
					}
				}
			}
		} else {
			if(debug){
				authResults.debug.diedOn = "all headers not present! You are missing one or more.";
			}
		}
		
		//credentials retrieved. IF NOT A GET, Decrypt the body, verify that payload is json
		if(proceed AND CGI.REQUEST_METHOD IS NOT "GET"){
			try{
				requestBody = decrypt(ToString(getHTTPRequestData().content),qryCreds.ekey,"AES","base64");
			} catch(any e){
				proceed = false;
				if(debug){
					authResults.debug.diedOn = "attempting to decrypt, encountered error: #e.message#";
					authResults.debug.originalBody = ToString(getHTTPRequestData().content);
				}
			}
			
			if(proceed){
				if(NOT isJSON(requestBody)){
					proceed = false;
					if(debug){
						authResults.debug.diedOn = "decrypted body is not JSON";
						authResults.debug.decryptedbody = requestBody;
					}
				}
			}
		}
		
		//Payload is json OR this is a GET call and we didn't care about the payload. Create the hmac and compare it to incoming authtoken
		if(proceed){
			try{
				thisHMAC = makeHMAC(thisURL,requestBody,CGI.REQUEST_METHOD,qryCreds.privkey);
			} catch (any e){
				proceed = false;
				if(debug){
					authResults.debug.diedOn = "attempting to create HMAC, encountered error: #e.message#";
					authResults.debug.hmacParams = {thisURL=thisURL,requestBody=requestBody,method=cgi.request_method,privkey="its a secret!"};
				}
			}
			if(thisHMAC IS NOT getHTTPRequestData().headers.authtoken){
				proceed = false;
				if(debug){
					authResults.debug.diedOn = "HMACs do not match. You sent: #getHTTPRequestData().headers.authtoken# and we produced: #thisHMAC#";
					authResults.debug.hmacParams = {thisURL=thisURL,requestBody=requestBody,method=cgi.request_method,privkey="its a secret!"};
				}
			}
		}
		
		if(proceed){//success! Let's put the decrypted payload into the authResults and allow this request to go on its merry way
			authResults.data = (CGI.REQUEST_METHOD IS NOT "GET")?deserializeJSON(requestBody):{};
			authResults.authSuccess = true;
		} else {//this request failed our scrutiny. 
			authResults.authSuccess = false;
		}
		
		return authResults;
	}
	
	private boolean function headersPresent(required struct headersin,required string headersList){
		var retval = true;
		var element = "";
		for(element in listToArray(arguments.headersList)){
			if(not structkeyexists(arguments.headersin,element)){
				retval = false;
			}
		};
		return retval;
	}
	
	private query function getCreds(required string handle, required string publicKey){
		var retval = "";
		var queryService = new query(); 
		var result = "";
		
	    queryService.setDatasource(variables.dsn); 
	    queryService.setName("retval"); 

	    queryService.addParam(name="handle",value="#arguments.handle#",cfsqltype="cf_sql_varchar"); 
	    queryService.addParam(name="pubkey", value="#arguments.publicKey#",cfsqltype="cf_sql_varchar"); 
	    
	    result = queryService.execute(
		    sql="select l.ekey,l.privkey
				from consumers c inner join llaves l on c.id = l.consumerid
				where c.handle = :handle 
				and c.pubkey = :pubkey"
			); 
			
	    retval = result.getResult(); 
	    
	    return retval;
	}
	
	private string function makeHmac(
		required string targurl,
		required string msgbody,
		required string method,
		string privatekey = '#application.privatekey#'){
			
		var strHMAC = arguments.targurl & " " & arguments.method;
		
		if(arguments.method IS NOT "GET"){
			strHMAC &= arguments.msgbody;
		}
		
		return hmac("#strHMAC#",arguments.privatekey,"HmacSHA1");
		
	}
	
	public struct function encryptPayload(required any payload){
		var retval = {data="",msg="",success=true};
		var proceed = true;

		try{//retrieve the user's credentials
			var qryCreds = getCreds(getHTTPRequestData().headers.handle,getHTTPRequestData().headers.pubkey);
		} catch (any e){
			proceed = false;
			retval.success = false;
			retval.msg = "attempting to encrypt return value, died getting creds. error: #e.Message#";
		}	

		
		retval.data = arguments.payload;

		if(proceed){			
			try{
				retval.data = encrypt((!isSimpleValue(retval.data))?serializeJSON(retval.data):retval.data,qryCreds.ekey,"AES","base64");
			} catch(any e){
				proceed = false;
				retval.msg = "attempting to encrypt results of method call, encountered error: #e.message# #e.detail#";
				retval.success=false;
			}
		}
		
		return retval;
	}

/**
* @hint I am called by all methods who wish to return data. The calling proxy is expecting a very specific payload structure which I create.
* @data I am the data structure being returned to the consumer; what they are actually after. If something goes awry in creating this payload, I will return an empty struct
* @authResults I am a structure of information regarding the authentication of this call. 
* @error I am an error message that the process calling us wishes to pass along to the consumer.
* @debug I am a debug structure that the process calling us wishes to pass along to the consumer.
* @success I am the success status of the process calling us. I will be passed along to the consumer.
*/
	public struct function makePayload(required any data="",required struct authResults,string error="",struct debug={},required boolean success){
		//I will accept the authresults and any data structure and prep them for return to our caller as a json string
		var retval = {
			createPayloadSuccess=true,
			processSuccess=arguments.success,
			authResults=arguments.authResults,
			data="",
			error={message=arguments.error,debug={}}
			};
			
		//if the consumer passed us a 'debug' header with a value of true, we'll allow any extra debug info supplied to be returned
		var debug = (structkeyexists(getHTTPRequestData().headers,"debug") AND getHTTPRequestData().headers.debug IS true)?true:false;
		if(debug){retval.error.debug = arguments.debug;}
		
		//encrypt our payload even if it's empty. The consumer is expecting an encrypted payload
		var eData = encryptPayload(arguments.data);
		if(eData.success){
			retval.data = eData.data;//the serialized, encrypted version of our retval	
		} else {//we encountered a problem trying to encrypt our return payload
			retval.error.message &= (retval.error.message IS NOT "")?" | #eData.msg#":"#eData.msg#";
			retval.createPayloadSuccess = false;
			//we'll just return the raw unencrypted data struct
		}
		return retval;
	}
}