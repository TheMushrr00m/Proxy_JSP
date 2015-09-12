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
%>

<!-- Begins the interesting code. -->
<%
String req_url = request.getQueryString();
// Just for testing...
out.println("<h1> The URL is: </h1>" + req_url); 
try {
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
 
} catch(Exception e) {
    response.setStatus(500);
}
%>