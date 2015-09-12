<!-- 
    Document   : Proyecto JSP - Web Proxy

    Created on : 2/09/2015, 06:22:50 PM
    Author     : Gabriel Cueto Báez
    Web        : http://laesporadelhongo.com/
-->
<!-- =======================
        Start the JSP code 
    ======================== -->

<%@page session="false" %>
<!-- Initiatig the imports -->
<%@page import=
"java.net.*,
java.io.*,
java.util.Map,
java.util.HashMap,
java.util.Enumeration" %>

<!-- Initiating declaration. -->
<%! 
    // Set the default values of the proxy.
    // Change 'localhost' for the proxy address.
    // If you do not use a port different of '80', you do not need to 
    // specify at the address.
    String PROXY_ADDR = "http://localhost:8080/Proxy_JSP/proxy.jsp";
    URL url;
    // Gets the url that the user want to access.
    String req_url; // = request.getQueryString(); || req_url = request.getParameter("parameter");
    ServerUrl serverUrl;
    HttpURLConnection con;

    public static class ServerUrl {
        String url;
        public ServerUrl(String url){
            this.url = url;
        }
        public String getUrl(){
            return this.url;
        }
        public void setUrl(String value){
            this.url = value;
        }
    }

    // Change the URL into 'https' format.
    private String get_Full_Url(String url){
        if(url.startsWith("//")){
            url = url.replace("//","https://");
        } 
        else if(url.startsWith("www")){
            url = url.replace("www", "https://www");
        }
        else if(url.startsWith("http://")){
            url = url.replace("http://", "https://");    
        }
        return url;
    }

    // Process the request body sent by the client.
    private byte[] read_Request_Body(HttpServletRequest request) throws IOException{
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
        return new byte[1];
    }

    // Simplified interface of doHTTPRequest, will eventually call the complete interface of doHTTPRequest
    private HttpURLConnection doHTTPRequest(String uri, String method) throws IOException{
        //build the bytes sent to server
        byte[] bytes = null;

        //build the header sent to server
        HashMap<String, String> headerInfo = new HashMap<String, String>();
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

    //complete interface of doHTTPRequest
    private HttpURLConnection doHTTPRequest(String uri, byte[] bytes, String method, Map mapHeaderInfo) throws IOException{
        URL url = new URL(uri);
        HttpURLConnection con = (HttpURLConnection)url.openConnection();

        con.setConnectTimeout(5000);
        con.setReadTimeout(10000);
        con.setRequestMethod(method);

        //pass the header to the proxy's request
        //passHeadersInfo(mapHeaderInfo, con);

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

    // Sends the actual request to the server.
    private HttpURLConnection forwardToServer(HttpServletRequest request, String uri, byte[] postBody) throws IOException{
        //copy the client's request header to the proxy's request
        Enumeration headerNames = request.getHeaderNames();
        HashMap<String, String> mapHeaderInfo = new HashMap<String, String>();
        while (headerNames.hasMoreElements()) {
            String key = (String) headerNames.nextElement();
            String value = request.getHeader(key);
            if (!key.equalsIgnoreCase("host")) mapHeaderInfo.put(key, value);
        }
        if(postBody.length > 0){ return doHTTPRequest(uri, postBody, "POST", mapHeaderInfo); }
        else { return doHTTPRequest(uri, request.getMethod()); }
    }
%>

<!-- Begins the interesting code. -->
<%
req_url = request.getQueryString();
// Just for testing...
out.println("Introduced URL: " + req_url);
try {
    if(req_url == null || req_url.isEmpty()){}
    else{
        req_url = get_Full_Url(req_url);
        url = new URL(req_url);    
        // Just for testing...
        out.println("ModifiedURL: "+url);
        out.println("ContentLength: "+request.getContentLength());
    }   
    con = (HttpURLConnection) url.openConnection();
    con.setDoOutput(true);
    con.setRequestMethod(request.getMethod());
    byte[] post_Body = read_Request_Body(request);
    String post = new String(post_Body);
    forwardToServer(request, req_url, post_Body);
    // Just for testing...
    out.println("RequestBody: " + forwardToServer(request, req_url, post_Body));
} catch(Exception e) {
    response.setStatus(500);
}
/*
    String reqUrl = request.getQueryString(); //OR:  request.getParameter("url");
    URL url = new URL(reqUrl);
    HttpURLConnection con = (HttpURLConnection)url.openConnection();
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
 */
%>