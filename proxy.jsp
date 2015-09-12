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
java.io.*" %>

<!-- Initiating declaration. -->
<%! 
    // Set the default values of the proxy.
    // Change 'localhost' for the proxy address.
    // If you do not use a port different of '80', you do not need to 
    // specify at the address.
    String PROXY_ADDR = "http://localhost/Proxy_JSP/proxy.jsp";
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
        return new byte[0];
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
    }   
    con = (HttpURLConnection) url.openConnection();
    con.setDoOutput(true);
    con.setRequestMethod(request.getMethod());
    // Just for testing...
    out.println(""+read_Request_Body(request));
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