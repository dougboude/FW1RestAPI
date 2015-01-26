<cfheader statuscode="500" statustext="An error has occurred" />
<h1>An error occurred</h1>
<!---<cfset sstring = {name="Doug",last="boude",bla="so what!"} />
<cfset thekey = GenerateSecretKey("AES" ,128) />
<cfset estring = encrypt(serializeJSON(sstring),thekey,"AES","base64") />
<cfset ostring = deserializeJSON(decrypt(estring,thekey,"AES","base64")) />
<cfoutput>thekey: #thekey# --- thestring: #estring# </cfoutput><br>
<cfdump var="#ostring#">--->
<!---<cfoutput>
	<cfset headers = getHttpRequestData().headers />
	ajax? #structKeyExists(headers, "X-Requested-With") && (headers["X-Requested-With"] eq "XMLHttpRequest")#
	<hr>
	#serializeJSON(headers)#
	<hr>
	#serializeJSON(cgi)#
	
</cfoutput><cfabort>--->
<cfoutput>
	
<cfif structKeyExists(request, "exception")>
	<h2>#request.exception.message#</h2>
	<section class="error">
	<p><strong>Message:</strong> #request.exception.message#</p>
	<p><strong>Root Cause Message:</strong> #request.exception.rootCause.message#</p>
	<cfif isDefined("request.exception.rootCause.detail") AND request.exception.rootCause.detail NEQ "">
	<p><strong>Root Cause Detail:</strong>>#request.exception.rootCause.detail#</p>
	</cfif>
	</section>
	<cftry>
	<h2>RC</h2>
	<cfdump var="#rc#" />
	<cfcatch type="any">
	<em>RC is not available.</em>
	</cfcatch>
	</cftry>
	<h2>Exception Detail</h2>
	<cfdump var="#request.exception#" />
</cfif>	
	<h2>CGI</h2>
	<cfdump var="#cgi#" />
	<h2>Server</h2>
	<cfdump var="#server#" />
	<h2>Session</h2>
	<cfdump var="#session#" />

</cfoutput>