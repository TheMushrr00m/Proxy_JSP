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
java.io.*" %>
<%
try 
{
    // Gets the url that the user want to access.
	String req_url = request.getQueryString();
    //int time_out = 6000;
    //String req_url = request.getParameter("uri"); 
    URL url = new URL(req_url);
    HttpURLConnection con = (HttpURLConnection) url.openConnection();
    con.setDoOutput(true);
    con.setRequestMethod(request.getMethod());
    int clength = request.getContentLength();
    if(clength > 0) 
    {   
        con.setDoInput(true);
        byte[] idata = new byte[clength];
        request.getInputStream().read(idata, 0, clength);
        con.getOutputStream().write(idata, 0, clength);
    }
    %>

    <!-- Remove the "messages" of the page when initiating a connection with the site that the user tries to access -->
    <script type="text/javascript">
        var messages = document.getElementById('messages');
        messages.parentNode.removeChild(messages);
    </script>

<%
    response.setContentType(con.getContentType());
	BufferedReader rd = new BufferedReader(new InputStreamReader(con.getInputStream()));
    String line;
    while ((line = rd.readLine()) != null)         
    {
        out.println(line); 
    }
    rd.close();
    response.setStatus(200); 
} catch(Exception e) 
{
	response.setStatus(500);
}
%>
