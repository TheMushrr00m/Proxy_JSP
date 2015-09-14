<!-- 
    Document   : Proyecto JSP - Web Proxy

    Created on : 2/09/2015, 06:22:50 PM
    Author     : Gabriel Cueto Báez
    Web        : http://laesporadelhongo.com/
-->

<%@page session="false" %>
<!--  ==================================
           Start the JSP code 
      ================================== 
          Initiatig the imports --> 
<%@page import="
    java.net.*,
    java.io.*,
    java.util.Map,
    java.util.Set,
    java.util.HashMap,
    java.util.Enumeration,
    java.util.List" 
%>

<%! 
    /* ====================================
            Initiating declaration. 
       ==================================== */

    // Gets the url that the user want to access.
    String req_url; // = request.getQueryString(); || req_url = request.getParameter("parameter");
    HttpURLConnection con;
    URL url;

    public static final class DataValidUtil {
        public static String removeCRLF(String inputLine) {
            String filteredLine = inputLine;
            if (hasCRLF(inputLine)) {
                filteredLine = filteredLine.replace("\n","").replace("\r","");
            }
            return filteredLine;
        }
        public static boolean hasCRLF(String inputLine) {
            return inputLine.contains("\n") || inputLine.contains("\r");
        }
    }

    // Change the URL into 'https' format.
    private String get_Full_Url(String _url) throws UnsupportedEncodingException{
        if(_url.startsWith("//")){
            _url = _url.replace("//","http://");
        } 
        else if(_url.startsWith("localhost")){
            _url = _url.replace("localhost","http://localhost");    
        }
        else if(_url.startsWith("www")){
            _url = _url.replace("www", "http://www");
        }
        else if(_url.startsWith("http://")){}
        else if (_url.toLowerCase().startsWith("http%3a%2f%2f") || _url.toLowerCase().startsWith("https%3a%2f%2f")){ 
            _url = URLDecoder.decode(_url, "UTF-8");
        }
        return _url;
    }

    // Process the request body sent by the client.
    private byte[] read_Request_Body(HttpServletRequest request) throws IOException{
        int clength = request.getContentLength();
        if(clength > 0) {
            byte[] bytes = new byte[clength];
            DataInputStream dataIs = new DataInputStream(request.getInputStream());
            dataIs.readFully(bytes);
            dataIs.close();
            return bytes;
        }
        return new byte[0];
    }

    // Simplified interface of doHTTPRequest, will eventually call the complete interface of doHTTPRequest.
    private HttpURLConnection doHTTPRequest(String uri, String method) throws IOException{
        // Build the bytes sent to server.
        byte[] bytes = null;
        // Build the header sent to server.
        HashMap<String, String> headerInfo = new HashMap<String, String>();
        //headerInfo.put("Referer", PROXY_ADDR);
        if (method.equals("POST")){
            String[] uriArray = uri.split("\\?", 2);
            uri = uriArray[0];
            System.out.println(uri);
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
        url = new URL(uri);
        con = (HttpURLConnection)url.openConnection();
        con.setConnectTimeout(5000);
        con.setReadTimeout(10000);
        con.setRequestMethod(method);
        // If it is a POST request.
        if (bytes != null && bytes.length > 0 || method.equals("POST")){
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

<%
/* 
    ====================================
        Begins the interesting code. 
    ==================================== */
req_url = request.getQueryString(); 
try {
    if(req_url == null || req_url.isEmpty()){ response.setStatus(400); }
    else{
        req_url = get_Full_Url(req_url);
        url = new URL(req_url);  
        byte[] post_Body = read_Request_Body(request);
        String post = new String(post_Body);
        con = forward_To_Server(request, req_url, post_Body);
        fetch_And_Pass_Back_To_Client(con, response);
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
                padding: 1px;
                background-color: #ffffff;
            }
            img{
                float: left;
            }
            h1, h2{
                margin-top: 0px;
                margin-bottom: 1px;
                color: #005288;
                text-align: center;
                font-style: italic;
                text-shadow: 1px 1px 0px #333, 1px 1px 0px #333;
            }
            p{
                margin-top: 2px;
                font-style: italic;
            }
            .form{
                font-size: 20px;
                color: #005288;
                text-decoration:none;
                text-align: center;
            }
            .button{
                background: #006699;
                border: none;
                color: #ffffff;
                font: 13px Tahoma, Arial, sans-serif;
                padding: 10px 15px;
                text-decoration: none;
                cursor: pointer;
                border: 1px solid #333;
                letter-spacing: 1px;

                /* Text shadow */
                text-shadow: 0px -1px 0px #333333;

                border-radius: 5px;
                /* Mozilla Firefox */
                -moz-border-radius: 5px;
                /* Chrome and Safari */
                -webkit-border-radius: 5px;

                /* Gradient */
                /*  Chrome and Safari  */
                background-image: -webkit-linear-gradient(top, #8b8b8b, #707070 50%, #5e5e5e 50%, #777777);
                /*  Mozilla Firefox  */
                background-image: -moz-linear-gradient(top, #8b8b8b, #707070 50%, #5e5e5e 50%, #777777);
                /*  IE 10+  */
                background-image: -ms-linear-gradient(top, #8b8b8b, #707070 50%, #5e5e5e 50%, #777777);
                /*  Opera  */
                background-image: -o-linear-gradient(top, #8b8b8b, #707070 50%, #5e5e5e 50%, #777777);
                background-image: linear-gradient(top, #8b8b8b, #707070 50%, #5e5e5e 50%, #777777);
            }
            .button:hover {
                /*  Chrome and Safari  */
                background-image: -webkit-linear-gradient(top, #5d5d5d, #424242 50%, #383838 50%, #535353);
                /*  Mozilla Firefox */
                background-image: -moz-linear-gradient(top, #5d5d5d, #424242 50%, #383838 50%, #535353);
                /*  IE 10+  */
                background-image: -ms-linear-gradient(top, #5d5d5d, #424242 50%, #383838 50%, #535353);
                /*  Opera */
                background-image: -o-linear-gradient(top, #5d5d5d, #424242 50%, #383838 50%, #535353);
                background-image: linear-gradient(top, #5d5d5d, #424242 50%, #383838 50%, #535353);
            }
            .button:active {
                /*  Chrome and Safari  */
                background-image: -webkit-linear-gradient(top, #000000, #2b2b2b 5%, #434343 50%, #3e3e3e);
                /*  Mozilla Firefox */
                background-image: -moz-linear-gradient(top, #000000, #2b2b2b 5%, #434343 50%, #3e3e3e);
                /*  IE 10+  */
                background-image: -ms-linear-gradient(top, #000000, #2b2b2b 5%, #434343 50%, #3e3e3e);
                /*  Opera */
                background-image: -o-linear-gradient(top, #000000, #2b2b2b 5%, #434343 50%, #3e3e3e);
                background-image: linear-gradient(top, #000000, #2b2b2b 5%, #434343 50%, #3e3e3e);
            }
        </style>
    </head>
    <body>
        <img  src="//oropezasc.com/wp-content/uploads/2015/08/110.png?77b37e">
        <h1> Welcome!! </h1>
        <div class="form">
            <form action="proxy.jsp" name="uri" method="POST">
                <input type="uri" placeholder="http://www.google.com" required>
                 <button type="submit" class="button">Go to!</button>
            </form>
            <p>Introduce the URL!!</p>
            <p>In this moment, is not working with introducing the URL into the textbox.</p>
            <h2> Please introduce the URL into the address bar. </h2>
        </div>
    </body>
</html>