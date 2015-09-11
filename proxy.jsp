<!-- 
    Document   : Proyecto JSP - Web Proxy

    Created on : 2/09/2015, 06:22:50 PM
    Author     : Gabriel Cueto Báez
    Web        : http://laesporadelhongo.com/
-->

<%@page contentType="text/html" pageEncoding="utf-8"%>
<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
        <title> Intranet Proxy!! </title>
        <style type="text/css">
        h1, h2{
            color: #50ee99;
        }
        body{
            background-color: #7e8f86;
        }
        </style>
        <script type="text/javascript">
            /*Remove the "messages" of the page when initiating a connection with the site that the user tries to access */
            var clearMessages = function(){
                var messages = document.getElementById('messages');
                messages.parentNode.removeChild(messages);
            }
    </script>
    </head>
    <body>
        <div id="messages">
            <h1>Work in progress...</h1>
            <h2>Testing connection...</h2>
        </div>
        <form action="index.jsp" name="uri" method="POST">
            <!--<input type="uri" placeholder="http://www.oropezasc.com/" required>
            <input type="submit" value="Go to!">-->
        </form>
    </body>
</html>

<!-- Start the JSP code -->
<%@page session="false" %>
<%@page import=
"java.net.*,
java.io.BufferedReader,
java.io.ByteArrayOutputStream,
java.io.DataInputStream,
java.io.FileNotFoundException,
java.io.IOException,
java.io.InputStream,
java.io.InputStreamReader,
java.io.OutputStream,
java.io.Reader,
java.util.Date,
java.util.concurrent.ConcurrentHashMap,
java.util.Map,
java.util.Set,
java.util.regex.Matcher,
java.util.regex.Pattern,
java.util.ArrayList,
java.util.logging.Logger,
java.util.logging.FileHandler,
java.util.logging.SimpleFormatter,
java.util.logging.Level,
java.util.List,
java.util.Iterator,
java.util.Enumeration,
java.util.HashMap,
java.text.SimpleDateFormat" %>

<!-- Initiating declaration. -->
<%! 
    // Set the default values of the proxy.
    // Change 'localhost' for the proxy address.
    // If you do not use a port different of '80', you do not need to 
    // specify at the address.
    //String PROXY_ADDR = "http://localhost:8080/proxy.jsp";
    String PROXY_REFERER = "http://localhost:8080/proxy.jsp";
    // Gets the url that the user want to access.
    String req_url; // = request.getQueryString(); req_url = request.getParameter("parameter");
    URL url;
    HttpURLConnection con;
    ServerUrl[] serverUrls;
    boolean mustMatch;  
    //int time_out = 6000;
    //String sourceIP = request.getRemoteAddr();

    // setReferer if real referer exist
    private void setReferer(String r) {
        PROXY_REFERER = r;
    }

    public void setServerUrls(ServerUrl[] value){
        this.serverUrls = value;
    }

    public boolean getMustMatch(){
        return this.mustMatch;
    }

    public void setMustMatch(boolean value){
        this.mustMatch = value;
    }

    public static class ServerUrl {
        String url;
        boolean matchAll;
        String hostRedirect;
        public ServerUrl(String url, String matchAll, String hostRedirect){
            this.url = url;
            this.matchAll = matchAll == null || matchAll.isEmpty() || Boolean.parseBoolean(matchAll);
            this.hostRedirect = hostRedirect;
        }
        public ServerUrl(String url){
            this.url = url;
        }
        public String getUrl(){
            return this.url;
        }
        public void setUrl(String value){
            this.url = value;
        }
        public boolean getMatchAll(){
            return this.matchAll;
        }
        public void setMatchAll(boolean value){
            this.matchAll = value;
        }
        public String getHostRedirect() {
            return hostRedirect;
        }
        public void setHostRedirect(String hostRedirect) {
            this.hostRedirect = hostRedirect;
        }
    }

    // Process the request body sent by the client.
    private byte[] readRequestBody(HttpServletRequest request) throws IOException{
        int clength = request.getContentLength();
        if(clength > 0) {
            //con.setDoInput(true);
            byte[] bytes = new byte[clength];
            //request.getInputStream().read(bytes, 0, clength);
            //con.getOutputStream().write(bytes, 0, clength);
            DataInputStream dataIs = new DataInputStream(request.getInputStream());
            dataIs.readFully(bytes);
            dataIs.close();
            return bytes;
        }
        return new byte[0];
    }

    // Copy header info to the proxy's request
    private boolean passHeadersInfo(Map mapHeaderInfo, HttpURLConnection con) {
        Iterator headerIterator = mapHeaderInfo.entrySet().iterator();
        while (headerIterator.hasNext()) {
            Map.Entry pair = (Map.Entry)headerIterator.next();
            con.setRequestProperty(pair.getKey().toString(),pair.getValue().toString());
            headerIterator.remove(); // avoids a ConcurrentModificationException
        }
        return true;
    }

    // Complete interface of doHTTPRequest.
    private HttpURLConnection doHTTPRequest(String uri, byte[] bytes, String method, Map mapHeaderInfo) throws IOException{
        URL url = new URL(uri);
        HttpURLConnection con = (HttpURLConnection)url.openConnection();
        con.setConnectTimeout(5000);
        con.setReadTimeout(10000);
        con.setRequestMethod(method);
        //pass the header to the proxy's request
        passHeadersInfo(mapHeaderInfo, con);
        //if it is a POST request
        if (bytes != null && bytes.length > 0 || method.equals("POST")) {
            if (bytes == null){
                bytes = new byte[0];
            }
            con.setRequestMethod("POST");
            con.setDoOutput(true);
            OutputStream os = con.getOutputStream();
            os.write(bytes);
        }
        return con;
    }

    // Simplified interface of doHTTPRequest, will eventually call the complete interface of doHTTPRequest.
    private HttpURLConnection doHTTPRequest(String uri, String method) throws IOException{
        //build the bytes sent to server
        byte[] bytes = null;
        //build the header sent to server
        HashMap<String, String> headerInfo=new HashMap<>();
        headerInfo.put("Referer", PROXY_REFERER);
        if (method.equals("POST")){
            String[] uriArray = uri.split("\\?", 2);
            uri = uriArray[0];
            headerInfo.put("Content-Type", "application/x-www-form-urlencoded");
            if (uriArray.length > 1){
                String queryString = uriArray[1];
                bytes = queryString.getBytes("UTF-8");
            }
        }
        return doHTTPRequest(uri, bytes, method, headerInfo);
    }

    // Proxy sends the actual request to the server.
    private HttpURLConnection forwardToServer(HttpServletRequest request, String uri, byte[] postBody) throws IOException{
        //copy the client's request header to the proxy's request
        Enumeration headerNames = request.getHeaderNames();
        HashMap<String, String> mapHeaderInfo = new HashMap<>();
        while (headerNames.hasMoreElements()) {
            String key = (String) headerNames.nextElement();
            String value = request.getHeader(key);
            if (!key.equalsIgnoreCase("host")) mapHeaderInfo.put(key, value);
        }
        return 
                postBody.length > 0 ?
                    doHTTPRequest(uri, postBody, "POST", mapHeaderInfo) :
                    doHTTPRequest(uri, request.getMethod());
    }

    // Poxy gets the response back from server.
    private boolean fetchAndPassBackToClient(HttpURLConnection con, HttpServletResponse clientResponse, boolean ignoreAuthenticationErrors) throws IOException{
        if (con!=null){
            Map<String, List<String>> headerFields = con.getHeaderFields();
            Set<String> headerFieldsSet = headerFields.keySet();
            //copy the response header to the response to the client
            for (String headerFieldKey : headerFieldsSet){
                //prevent request for partial content
                if (headerFieldKey != null && headerFieldKey.toLowerCase().equals("accept-ranges")){
                    continue;
                }
                List<String> headerFieldValue = headerFields.get(headerFieldKey);
                StringBuilder sb = new StringBuilder();
                for (String value : headerFieldValue) {
                    sb.append(value);
                    sb.append("");
                }
                if (headerFieldKey != null){
                    clientResponse.addHeader(headerFieldKey, DataValidUtil.removeCRLF(sb.toString()));
                }
            }
            //copy the response content to the response to the client
            InputStream byteStream;
            if (con.getResponseCode() >= 400 && con.getErrorStream() != null){
                if (ignoreAuthenticationErrors && (con.getResponseCode() == 498 || con.getResponseCode() == 499)) return true;
                byteStream = con.getErrorStream();
            }else{
                byteStream = con.getInputStream();
            }
            clientResponse.setStatus(con.getResponseCode());

            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            final int length = 5000;
            byte[] bytes = new byte[length];
            int bytesRead;
            while ((bytesRead = byteStream.read(bytes, 0, length)) > 0) {
                buffer.write(bytes, 0, bytesRead);
            }
            buffer.flush();
            //if the content of the HttpURLConnection contains error message, it means the token expired, so let proxy try again
            String strResponse = buffer.toString();
            if (!ignoreAuthenticationErrors && strResponse.contains("error") && (strResponse.contains("\"code\": 498") || strResponse.contains("\"code\": 499")
                    || strResponse.contains("\"code\":498") || strResponse.contains("\"code\":499"))) {
                return true;
            }
            byte[] byteResponse = buffer.toByteArray();
            OutputStream ostream = clientResponse.getOutputStream();
            ostream.write(byteResponse);
            ostream.close();
            byteStream.close();
        }
        return false;
    }

    // Convert response from InputStream format to String format
    private String webResponseToString(HttpURLConnection con) throws IOException{
        InputStream in = con.getInputStream();
        Reader reader = new BufferedReader(new InputStreamReader(in, "UTF-8"));
        StringBuilder content = new StringBuilder();
        char[] buffer = new char[5000];
        int n;
        while ( ( n = reader.read(buffer)) != -1 ) {
            content.append(buffer, 0, n);
        }
        reader.close();
        return content.toString();
    }

    private boolean pathMatched(String allowedRefererPath, String refererPath){
        //If equal, return true
        if (refererPath.equals(allowedRefererPath)){
            return true;
        }
        //If the allowedRefererPath contain a ending star and match the begining part of referer, it is proper start with.
        if (allowedRefererPath.endsWith("*")){
            allowedRefererPath = allowedRefererPath.substring(0, allowedRefererPath.length()-1);
            if (refererPath.toLowerCase().startsWith(allowedRefererPath.toLowerCase())){
                return true;
            }
        }
        return false;
    }

    private boolean domainMatched(String allowedRefererDomain, String refererDomain) throws MalformedURLException{
        if (allowedRefererDomain.equals(refererDomain)){
            return true;
        }
        //try if the allowed referer contains wildcard for subdomain
        if (allowedRefererDomain.contains("*")){
            if (checkWildcardSubdomain(allowedRefererDomain, refererDomain)){
                return true;//return true if match wildcard subdomain
            }
        }
        return false;
    }

    private boolean protocolMatch(String allowedRefererProtocol, String refererProtocol){
        return allowedRefererProtocol.equals(refererProtocol);
    }

    private boolean checkReferer(String[] allowedReferers, String referer) throws MalformedURLException{
        if (allowedReferers != null && allowedReferers.length > 0){
            if (allowedReferers.length == 1 && allowedReferers[0].equals("*")) {
                return true; //speed-up
            }
            for (String allowedReferer : allowedReferers){
                allowedReferer = allowedReferer.replaceAll("\\s", "");
                URL refererURL = new URL(referer);
                URL allowedRefererURL;
                //since the allowedReferer can be a malformedURL, we first construct a valid one to be compared with referer
                //if allowedReferer starts with https:// or http://, then exact match is required
                if (allowedReferer.startsWith("https://") || allowedReferer.startsWith("http://")){
                    allowedRefererURL = new URL(allowedReferer);
                } else {
                    String protocol = refererURL.getProtocol();
                    //if allowedReferer starts with "//" or no protocol, we use the one from refererURL to prefix to allowedReferer.
                    if (allowedReferer.startsWith("//")){
                        allowedRefererURL = new URL(protocol+":"+allowedReferer);
                    } else {
                        //if the allowedReferer looks like "example.esri.com"
                        allowedRefererURL = new URL(protocol+"://"+allowedReferer);
                    }
                }
                //Check if both domain and path match
                if (protocolMatch(allowedRefererURL.getProtocol(), refererURL.getProtocol()) &&
                        domainMatched(allowedRefererURL.getHost(), refererURL.getHost()) &&
                        pathMatched(allowedRefererURL.getPath(), refererURL.getPath())) {
                    return true;
                }
            }
            return false;//no-match in allowedReferer, does not allow the request
        }
        return true;//when allowedReferer is null, then allow everything
    }

     private String getFullUrl(String url){
        return url.startsWith("//") ? url.replace("//","https://") : url;
    }

    //===================================
    //              ERRORS
    //===================================

    private static void sendErrorResponse(HttpServletResponse response, String errorDetails, String errorMessage, int errorCode) throws IOException{
        response.setHeader("Content-Type", "application/json");
        String message = "{" +
                "\"error\": {" +
                "\"code\": " + errorCode + "," +
                "\"details\": [" +
                "\"" + errorDetails + "\"" +
                "], \"message\": \"" + errorMessage + "\"}}";
        response.setStatus(errorCode);
        OutputStream output = response.getOutputStream();
        output.write(message.getBytes());
        output.flush();
    }

    private static void _sendURLMismatchError(HttpServletResponse response, String attemptedUri) throws IOException{
        sendErrorResponse(response, "Proxy has not been set up for this URL. Make sure there is a serverUrl in the configuration file that matches: " + attemptedUri,
                "Proxy has not been set up for this URL.", HttpServletResponse.SC_FORBIDDEN);
    }
    private static void _sendPingMessage(HttpServletResponse response, String version, String config, String log) throws IOException{
        response.setStatus(HttpServletResponse.SC_OK);
        response.setHeader("Content-Type", "application/json");
        String message = "{ " +
                "\"Proxy Version\": \"" + version + "\"" +
                //", \"Java Version\": \"" + System.getProperty("java.version") + "\"" +
                ", \"Configuration File\": \"" + config + "\""  +
                ", \"Log File\": \"" + log + "\"" +
                "}";
        OutputStream output = response.getOutputStream();
        output.write(message.getBytes());
        output.flush();
    }
    // Check if the originalUri needs to be host-redirected.
    private String uriHostRedirect(String originalUri, ServerUrl serverUrl) throws MalformedURLException{
        if (serverUrl.hostRedirect != null && !serverUrl.hostRedirect.isEmpty()){
            URL request = new URL(originalUri);
            String redirectHost = serverUrl.getHostRedirect();
            redirectHost = redirectHost.endsWith("/")?redirectHost.substring(0, redirectHost.length()-1):redirectHost;
            String queryString = request.getQuery();
            return redirectHost + request.getPath() + ((queryString != null) ? ("?" + queryString) : "");
        }
        return originalUri;
    }
%>

<!-- Begins the interesting code. -->
<%
ServerUrl serverUrl;
String originalUri = request.getQueryString();
try {
        try {
            out.clear();
            out = pageContext.pushBody();
            //check if the originalUri to be proxied is empty
            if (originalUri == null || originalUri.isEmpty()){
                String errorMessage = "This proxy does not support empty parameters.";
                _log(Level.WARNING, errorMessage);
                sendErrorResponse(response, errorMessage, "400 - " + errorMessage, HttpServletResponse.SC_BAD_REQUEST);
                return;
            }
            //check if the originalUri to be proxied is "ping"
            if (originalUri.equalsIgnoreCase("ping")){
                String checkConfig = getConfig().canReadProxyConfig() ? "OK": "Not Readable";
                String checkLog = okToLog() ? "OK": "Not Exist/Readable";
                _sendPingMessage(response, version, checkConfig, checkLog);
                return;
            }
            //check if the originalUri is encoded then decode it
            if (originalUri.toLowerCase().startsWith("http%3a%2f%2f") || originalUri.toLowerCase().startsWith("https%3a%2f%2f")) originalUri = URLDecoder.decode(originalUri, "UTF-8");
            //check the Referer in request header against the allowedReferer in proxy.config
            String[] allowedReferers = getConfig().getAllowedReferers();
            if (allowedReferers != null && allowedReferers.length > 0 && request.getHeader("referer") != null){
                setReferer(request.getHeader("referer")); //replace PROXY_REFERER with real proxy
                String httpReferer;
                try{
                    //only use the hostname of the referer url
                    httpReferer = new URL(request.getHeader("referer")).toString();
                }catch(Exception e){
                    _log(Level.WARNING, "Proxy is being used from an invalid referer: " + request.getHeader("referer"));
                    sendErrorResponse(response, "Error verifying referer. ", "403 - Forbidden: Access is denied.", HttpServletResponse.SC_FORBIDDEN);
                    return;
                }
                if (!checkReferer(allowedReferers, httpReferer)){
                    _log(Level.WARNING, "Proxy is being used from an unknown referer: " + request.getHeader("referer"));
                    sendErrorResponse(response, "Unsupported referer. ", "403 - Forbidden: Access is denied.", HttpServletResponse.SC_FORBIDDEN);
                    return;
                }
            }
            //Check to see if allowed referer list is specified and reject if referer is null
            if (request.getHeader("referer") == null && allowedReferers != null && !allowedReferers[0].equals("*")) {
                _log(Level.WARNING, "Proxy is being called by a null referer.  Access denied.");
                sendErrorResponse(response, "Current proxy configuration settings do not allow requests which do not include a referer header.", "403 - Forbidden: Access is denied.", HttpServletResponse.SC_FORBIDDEN);
                return;
            }
            //get the serverUrl from proxy.config
            serverUrl = getConfig().getConfigServerUrl(originalUri);
            if (serverUrl == null) {
                //if no serverUrl found, send error message and get out.
                _sendURLMismatchError(response, originalUri);
                return;
            }
        } catch (IllegalStateException e) {
            _log(Level.WARNING, "Proxy is being used for an unsupported service: " + originalUri);
            _sendURLMismatchError(response, originalUri);
            return;
        }
        //Throttling: checking the rate limit coming from particular referrer
        if ( serverUrl.getRateLimit() > -1) {
            synchronized(_rateMapLock){
                ConcurrentHashMap<String, RateMeter> ratemap = castRateMap(application.getAttribute("rateMap"));
                if (ratemap == null){
                    ratemap = new ConcurrentHashMap<>();
                    application.setAttribute("rateMap", ratemap);
                    application.setAttribute("rateMap_cleanup_counter", 0);
                }
                String key = "[" + serverUrl.getUrl() + "]x[" + request.getRemoteAddr() + "]";
                RateMeter rate = ratemap.get(key);
                if (rate == null) {
                    rate = new RateMeter(serverUrl.getRateLimit(), serverUrl.getRateLimitPeriod());
                    RateMeter rateCheck = ratemap.putIfAbsent(key, rate);
                    if (rateCheck != null){
                        rate = rateCheck;
                    }
                }
                if (!rate.click()) {
                    _log(Level.WARNING, "Pair " + key + " is throttled to " + serverUrl.getRateLimit() + " requests per " + serverUrl.getRateLimitPeriod() + " minute(s). Come back later.");
                    sendErrorResponse(response, "This is a metered resource, number of requests have exceeded the rate limit interval.",
                            "Error 429 - Too Many Requests", 429);
                    return;
                }
                //making sure the rateMap gets periodically cleaned up so it does not grow uncontrollably
                int cnt = (int) application.getAttribute("rateMap_cleanup_counter");
                cnt++;
                if (cnt >= CLEAN_RATEMAP_AFTER) {
                    cnt = 0;
                    cleanUpRatemap(ratemap);
                }
                application.setAttribute("rateMap_cleanup_counter", cnt);
            }
        }
        //readying body (if any) of POST request
        byte[] postBody = readRequestPostBody(request);
        String post = new String(postBody);
        //check if the originalUri needs to be host-redirected
        String requestUri = uriHostRedirect(originalUri, serverUrl);
        //if token comes with client request, it takes precedence over token or credentials stored in configuration
        boolean hasClientToken = requestUri.contains("?token=") || requestUri.contains("&token=") || post.contains("?token=") || post.contains("&token=");
        String token = "";
        if (!hasClientToken) {
            // Get new token and append to the request.
            // But first, look up in the application scope, maybe it's already there:
            token = (String)application.getAttribute("token_for_" + serverUrl.getUrl());
            boolean tokenIsInApplicationScope = token != null && !token.isEmpty();
            //if still no token, let's see if there are credentials stored in configuration which we can use to obtain new token
            if (!tokenIsInApplicationScope){
                token = getNewTokenIfCredentialsAreSpecified(serverUrl, requestUri);
            }
            if (token != null && !token.isEmpty() && !tokenIsInApplicationScope) {
                //storing the token in Application scope, to do not waste time on requesting new one until it expires or the app is restarted.
                application.setAttribute("token_for_" + serverUrl.getUrl(), token);
            }
        }
        //forwarding original request
        HttpURLConnection con = forwardToServer(request, addTokenToUri(requestUri, token), postBody);
        if ( token == null || token.isEmpty() || hasClientToken) {
            //if token is not required or provided by the client, just fetch the response as is:
            fetchAndPassBackToClient(con, response, true);
        } else {
            //credentials for secured service have come from configuration file:
            //it means that the proxy is responsible for making sure they were properly applied:
            //first attempt to send the request:
            boolean tokenRequired = fetchAndPassBackToClient(con, response, false);
            //checking if previously used token has expired and needs to be renewed
            if (tokenRequired) {
                _log(Level.INFO, "Renewing token and trying again.");
                //server returned error - potential cause: token has expired.
                //we'll do second attempt to call the server with renewed token:
                token = getNewTokenIfCredentialsAreSpecified(serverUrl, requestUri);
                con = forwardToServer(request, addTokenToUri(requestUri, token), postBody);
                //storing the token in Application scope, to do not waste time on requesting new one until it expires or the app is restarted.
                synchronized(this){
                    application.setAttribute("token_for_" + serverUrl.getUrl(), token);
                }
                fetchAndPassBackToClient(con, response, true);
            }
        }
    } catch (FileNotFoundException e){
        try {
            _log("404 Not Found .", e);
            response.sendError(404, e.getLocalizedMessage() + " is NOT Found.");
            return;
        }catch (IOException finalErr){
            _log("There was an error sending a response to the client.  Will not try again.", finalErr);
        }
    } catch (IOException e){
        try {
            _log("A fatal proxy error occurred.", e);
            response.sendError(500, e.getLocalizedMessage());
            return;
        } catch (IOException finalErr){
            _log("There was an error sending a response to the client.  Will not try again.", finalErr);
        }
    }
%>


    /*
    url = new URL(req_url);
    con = (HttpURLConnection) url.openConnection();
    con.setDoOutput(true);
    con.setRequestMethod(request.getMethod());
    int clength = request.getContentLength();
    if(clength > 0) {   
        con.setDoInput(true);
        byte[] idata = new byte[clength];   
        request.getInputStream().read(idata, 0, clength);
        con.getOutputStream().write(idata, 0, clength);
    }
    response.setContentType(con.getContentType());
    BufferedReader rd = new BufferedReader(new InputStreamReader(con.getInputStream()));
    String line;
    while ((line = rd.readLine()) != null) {
        out.println(line); 
    }
    rd.close();
    response.setStatus(200); 
} catch(Exception e) {
    response.setStatus(500); */
}
%>
