<!-- 
    Document   : Proyecto JSP - Web Proxy

    Created on : 2/09/2015, 06:22:50 PM
    Author     : Gabriel Cueto Báez
    Web        : http://laesporadelhongo.com/
-->
<!-- ==================================
            Start the JSP code 
    =================================== -->

<%@page session="false" %>
<!-- Initiatig the imports -->
<%@page import=
    "java.net.*,
    java.io.*,
    java.util.Map,
    java.util.Set,
    java.util.HashMap,
    java.util.Enumeration,
    java.util.List" 
%>

<!-- ====================================
            Initiating declaration. 
    ===================================== -->
<%! 
    /* Set the default values of the proxy.
    * Change 'localhost' for the proxy address.
    * If you do not use a port different of '80', you do not need to 
    * specify at the address. */
    String PROXY_ADDR = "http://localhost:8080/Proxy_JSP/proxy.jsp";
    URL url;
    // Gets the url that the user want to access.
    String req_url; // = request.getQueryString(); || req_url = request.getParameter("parameter");
    ServerUrl serverUrl;
    HttpURLConnection con;
    boolean flag;

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
    private String get_Full_Url(String _url) throws UnsupportedEncodingException{
        if(_url.startsWith("//")){
            _url = _url.replace("//","https://");
        } 
        else if(_url.startsWith("www")){
            _url = _url.replace("www", "https://www");
        }
        else if(_url.startsWith("http://")){
            _url = _url.replace("http://", "https://");    
        }
        else if (_url.toLowerCase().startsWith("http%3a%2f%2f") || _url.toLowerCase().startsWith("https%3a%2f%2f")){ 
            _url = URLDecoder.decode(_url, "UTF-8");
        }
        return _url;
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
        return new byte[0];
    }

    // Simplified interface of doHTTPRequest, will eventually call the complete interface of doHTTPRequest
    private HttpURLConnection doHTTPRequest(String uri, String method) throws IOException{
        //build the bytes sent to server
        byte[] bytes = null;

        // Build the header sent to server.
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

    // Complete interface of doHTTPRequest.
    private HttpURLConnection doHTTPRequest(String uri, byte[] bytes, String method, Map mapHeaderInfo) throws IOException{
        URL url = new URL(uri);
        HttpURLConnection con = (HttpURLConnection)url.openConnection();

        con.setConnectTimeout(5000);
        con.setReadTimeout(10000);
        con.setRequestMethod(method);

        // Pass the header to the proxy's request.
        // PassHeadersInfo(mapHeaderInfo, con);

        // If it is a POST request.
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
    private HttpURLConnection forward_To_Server(HttpServletRequest request, String uri, byte[] postBody) throws IOException{
        // Copy the client's request header to the proxy's request.
        Enumeration headerNames = request.getHeaderNames();
        HashMap<String, String> mapHeaderInfo = new HashMap<String, String>();
        while (headerNames.hasMoreElements()) {
            String key = (String) headerNames.nextElement();
            String value = request.getHeader(key);
            if (!key.equalsIgnoreCase("host")) mapHeaderInfo.put(key, value);
        }
        if(postBody.length > 0){ 
            return doHTTPRequest(uri, postBody, "POST", mapHeaderInfo); 
        }
        else{ 
            return doHTTPRequest(uri, request.getMethod()); 
        }
    }

    // Proxy gets the response back from server.
    private boolean fetch_And_Pass_Back_To_Client(HttpURLConnection con, HttpServletResponse clientResponse) throws IOException{
        if (con!=null){
            Map<String, List<String>> headerFields = con.getHeaderFields();
            Set<String> headerFieldsSet = headerFields.keySet();

            // Copy the response header to the response to the client.
            for (String headerFieldKey : headerFieldsSet){
                // Prevent request for partial content.
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

            // Copy the response content to the response to the client.
            InputStream byteStream;
            if (con.getResponseCode() >= 400 && con.getErrorStream() != null){
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

            // If the content of the HttpURLConnection contains error message, it means the token expired, so let proxy try again.
            String strResponse = buffer.toString();

            byte[] byteResponse = buffer.toByteArray();
            OutputStream ostream = clientResponse.getOutputStream();
            ostream.write(byteResponse);
            ostream.close();
            byteStream.close();
        }
        return false;
    }
%>

<!-- 
    ====================================
        Begins the interesting code. 
    ==================================== -->
<%
req_url = request.getQueryString();
try {
    if(req_url == null || req_url.isEmpty()){ response.setStatus(400); }
    else{
        req_url = get_Full_Url(req_url);
        serverUrl = new ServerUrl(PROXY_ADDR);
        url = new URL(req_url);    
        byte[] post_Body = read_Request_Body(request);
        String post = new String(post_Body);
        con = forward_To_Server(request, req_url, post_Body);
        flag = true;
        fetch_And_Pass_Back_To_Client(con, response);
        // Just for testing...
        out.println("<h1>FLAG: </h1>");
        /*con = (HttpURLConnection) url.openConnection();
        con.setDoOutput(true);
        con.setRequestMethod(request.getMethod());*/
        response.setStatus(200);
    }
} catch(Exception e) {
    response.setStatus(500);
}
%>

<!-- 
    ====================================
            Begins the HTML code 
    ==================================== -->

<%@page contentType="text/html" pageEncoding="UTF-8" %>
<!Doctype html>
<html lang="en-US">
    <head>
        <title> Proxy Project! </title>
        <meta charset="UTF-8">
        <link rel="icon" type="image/png" href="https://www.oropezasc.com/wp-content/uploads/2015/08/110-1.png?77b37e">
        <style type="text/css">
            body{
                background-color: #96a5a6;
            }
        </style>
    </head>
    <body>
        <h1> "Navigating under Proxy" </h1>
    </body>
</html>