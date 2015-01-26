<!---<cffunction name="headersPresent" returntype="boolean" access="private">
	<cfargument name="headersin" type="struct" required="true" />
	<cfargument name="headersList" type="string" required="true" />
	<cfset var retval = true />
	<cfloop list="#arguments.headersList#" index="i">
		<cfif not structkeyexists(arguments.headersin,i)>
			<cfset retval = false />
		</cfif>
	</cfloop>
	<cfreturn retval />
</cffunction>--->
<cfscript>
	public boolean function headersPresent(required struct headersin,required string headersList){
		var retval = true;
		var element = "";
		for(element in listToArray(arguments.headersList)){
			if(not structkeyexists(arguments.headersin,element)){
				retval = false;
			}
		};
		return retval;
	}
</cfscript>

<cfprocessingdirective pageencoding="utf-8" suppresswhitespace="true">
<cfsetting enablecfoutputonly="true" showdebugoutput="false" > 

<cfset proceed = true />
<cfset retval = {data={},debug={}} />
<cfset retval.debug.headersReceived = structcopy(getHTTPRequestData().headers) />
<cfset retval.debug.bodyfirst = getHTTPRequestData().content />

<cfcontent type="application/json">

<!---first, have we received the headers we're expecting? We need 'handle','pubkey', and 'authtoken'--->
<cfset expectedHeaders = "handle,pubkey,authtoken" />
<cfset proceed = headersPresent(headersin = getHTTPRequestData().headers,headersList=expectedHeaders) />

<cfif proceed>
	<cfset retval.debug.headersPresent = "true" />
<cfelse>
	<cfset retval.debug.headersPresent = "false" />
	<cfset retval.diedOn = "checking for headers" />
</cfif>


<cfif proceed>
<!---headers present. Retrieve this caller's other credentials--->		
	<cftry>
	<!---<cfquery name="qryGetCreds" datasource="#application.dsn#">
		select l.ekey,l.privkey
		from consumers c inner join llaves l on c.id = l.consumerid
		where c.handle = <cfqueryparam value="#getHTTPRequestData().headers.handle#" cfsqltype="cf_sql_varchar"  > 
		and c.pubkey = <cfqueryparam value="#getHTTPRequestData().headers.pubkey#" cfsqltype="cf_sql_varchar"  >
	</cfquery>--->
	<cfset qryGetCreds = getCreds(getHTTPRequestData().headers.handle,getHTTPRequestData().headers.pubkey) />
	
	<cfcatch type="any">
		<cfset proceed = false />
		<cfset retval.debug.diedOn = "attempting to query for creds. error: #cfcatch.Message#" />
	</cfcatch>	
	</cftry>
	
	<cfif proceed><!---query went well. Let's see what we retrieved. --->
		<cfif qryGetCreds.recordcount neq 1>
			<cfset proceed = false />
			<cfset retval.debug.diedOn = "we retrieved #qryGetCreds.recordcount# rows when looking up creds" />
		</cfif>
		<cfset retval.debug.lookupVals = {ekey=qryGetCreds.ekey,privkey=qryGetCreds.privkey} />
	</cfif>
</cfif>



<cfif proceed>
<!---credentials retrieved. IF NOT A GET, Decrypt the body, verify that payload is json--->
	<cfif CGI.REQUEST_METHOD IS NOT "GET">
		<cftry>
			<cfset bodyIn = decrypt(ToString(getHTTPRequestData().content),qryGetCreds.ekey,"AES","base64") />
		<cfcatch type="any">
			<cfset proceed = false />
			<cfset retval.debug.diedOn = "attempting to decrypt, encountered error: #cfcatch.message#" />
		</cfcatch>
		</cftry>
		
		<cfif proceed>
			<!---body decrypted. Let's test to see if it's JSON--->
			<cfif NOT isJSON(bodyIn)>
				<cfset proceed = false />
				<cfset retval.debug.diedOn = "decrypted body is not JSON" />
				<cfset retval.debug.decryptedbody = bodyIn />
				<cfset retval.debug.encryptedbody = ToString(getHTTPRequestData().content) />
			</cfif>
		</cfif>
	<cfelse>
		<cfset bodyIn = "" />
	</cfif>	
</cfif>

<cfif proceed>
<!---Payload is json OR this is a GET call. Create the hmac and compare it to incoming authtoken--->
	<cfset thisurl = GetPageContext().GetRequest().GetRequestUrl().toString() />
	<cfset thishmac = makeHMAC(thisurl,bodyIn,CGI.REQUEST_METHOD,qryGetCreds.privkey) />
	<cfset retval.debug.hmac = thishmac />
	<cfif thishmac IS NOT getHTTPRequestData().headers.authtoken>
		<cfset proceed = false />
		<cfset retval.debug.diedOn = "HMACs did not equal one another." />
	</cfif>
</cfif>

<cfif proceed>
	<!--- temp code to produce a body for get requests while testing --->
	<cfif CGI.REQUEST_METHOD IS "GET">
		<cfset bodyIn = {msg = "this was a get request and I am the payload requested"} />
		<cfset bodyIn = serializeJSON(bodyIn) />
	</cfif>
	
	<cfset retval.data.bodyIn = deserializeJSON(bodyIn)/>
	<!---hmacs match. Replace encrypted body with decrypted body in the request context--->
<cfelse><!--- something went awry. Need to redirect to our standard FAILURE! page. How much meaningful data should we provide? --->	

</cfif>




<cfheader name="success" value="#proceed#" />


<cfoutput>#serializeJSON(retval)#</cfoutput>



</cfprocessingdirective>

<!---<cffunction name="makeHmac2" returntype="string" access="private" output="false"
	hint="I receive several strings and produce an authentication token to be validated on the other side. This is my golden key">
	<cfargument name="targurl" type="string" required="yes" />
	<cfargument name="msgbody" type="string" required="yes" />
	<cfargument name="method" type="string" required="true" hint="I am needed as part of the hmac and to determine if body should be part of the hmac" />
	<cfargument name="privatekey" type="string" required="no" default="#application.privatekey#" />
	
	<cfset var strHMAC = arguments.targurl & " " & arguments.method />
	<cfif arguments.method IS NOT "GET">
		<cfset strHMAC = strHMAC & arguments.msgbody />
	</cfif>
	<!---<cfreturn strHMAC />--->
	<cfreturn hmac("#strHMAC#",arguments.privatekey,"HmacSHA1") />
</cffunction>--->
<cfscript>
	public string function makeHmac(
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

	private query function getCreds(required string handle, required string publicKey){
		var retval = "";
		var queryService = new query(); 
		var result = "";
		
	    queryService.setDatasource(application.dsn); 
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
</cfscript>

