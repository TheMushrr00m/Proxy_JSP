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
    String PROXY_ADDR = "http://localhost/Proxy_JSP/proxy.jsp";
    URL url;
    // Gets the url that the user want to access.
    String req_url; // = request.getQueryString(); OR req_url = request.getParameter("parameter");
    ServerUrl serverUrl;
    HttpURLConnection con;
    ServerUrl[] serverUrls;

    public static final class DataValidUtil {
        public static String removeCRLF(String inputLine) {
            String filteredLine = inputLine;
            if (hasCRLF(inputLine)) {
                filteredLine = filteredLine.replace("\n","").replace("\r","");
            }
            return filteredLine;
        }
        public static String replaceCRLF(String inputLine, String replaceString) {
            String filteredLine = inputLine;
            if (hasCRLF(inputLine)) {
                filteredLine = filteredLine.replace("\n",replaceString).replace("\r",replaceString);
            }
            return filteredLine;
        }
        public static boolean hasCRLF(String inputLine) {
            return inputLine.contains("\n") || inputLine.contains("\r");
        }
    }

    // setReferer if real referer exist
    private void setReferer(String r) {
        PROXY_ADDR = r;
    }

    public void setServerUrls(ServerUrl[] value){
        this.serverUrls = value;
    }

    public static class ServerUrl {
        String url;
        String hostRedirect;
        public ServerUrl(String url, String hostRedirect){
            this.url = url;
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
        public String getHostRedirect() {
            return this.hostRedirect;
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
        headerInfo.put("Referer", PROXY_ADDR);
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

    private boolean protocolMatch(String allowedRefererProtocol, String refererProtocol){
        return allowedRefererProtocol.equals(refererProtocol);
    }

     private String getFullUrl(String url){
        return url.startsWith("//") ? url.replace("//","https://") : url;
    }

    // Check if the req_url needs to be host-redirected.
    private String uriHostRedirect(String req_url, ServerUrl serverUrl) throws MalformedURLException{
        if (serverUrl.hostRedirect != null && !serverUrl.hostRedirect.isEmpty()){
            URL request = new URL(req_url);
            String redirectHost = serverUrl.getHostRedirect();
            redirectHost = redirectHost.endsWith("/")?redirectHost.substring(0, redirectHost.length()-1):redirectHost;
            String queryString = request.getQuery();
            return redirectHost + request.getPath() + ((queryString != null) ? ("?" + queryString) : "");
        }
        return req_url;
    }

    //===================================
    //              ERRORS
    //===================================

%>

<!-- Begins the interesting code. -->
<%
String req_url = request.getQueryString();
try {
        try {
            out.clear();
            out = pageContext.pushBody();
            // Check if the req_url to access into the proxy is empty.
            if (req_url == null || req_url.isEmpty()){
                return;
            }

            //check if the req_url is encoded then decode it
            if (req_url.toLowerCase().startsWith("http%3a%2f%2f") || req_url.toLowerCase().startsWith("https%3a%2f%2f")) req_url = URLDecoder.decode(req_url, "UTF-8");

            // Add your serverUrl
            serverUrl = (Url) req_url; 
            if (serverUrl == null) {
                return;
            }
        } catch (IllegalStateException e) {
            return;
        }
        // Readying body (if any) of POST request
        byte[] postBody = readRequestBody(request);
        String post = new String(postBody);
        // Check if the req_url needs to be host-redirected
        String requestUri = uriHostRedirect(req_url, serverUrl);
        // Forwarding original request
        HttpURLConnection con = forwardToServer(request, requestUri, postBody);
    } catch (FileNotFoundException e){
    }
%>