<!-- 
    Document   : Proyecto JSP - Web Proxy

    Created on : 2/09/2015, 06:22:50 PM
    Author     : Gabriel Cueto Báez
    Web        : http://laesporadelhongo.com/
-->

<!-- Send
<%@page contentType="text/html" pageEncoding="utf-8"%>
<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
        <title> Intranet Proxy </title>
    </head>
    <body>
        <form action="index.jsp" name="uri" method="POST">
            <!--<input type="url" placeholder="http://www.oropezasc.com/" required>
            <input type="submit" value="Go to!">-->
        </form>
    </body>
</html

<%@page session="false" %>
<%@page import=
"java.net.*,
java.io.*" %>

<%
try {
	String reqUrl = request.getQueryString(); //OR:  request.getParameter("url");
        //String reqUrl = request.getParameter("uri"); // Gets the url that the user write into the field.
        URL url = new URL(reqUrl);
        HttpURLConnection con = (HttpURLConnection)url.openConnection();
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
        response.setContentType(con.getContentType());
        
	BufferedReader rd = new BufferedReader(new InputStreamReader(con.getInputStream()));
        String line;
        while ((line = rd.readLine()) != null) 
        {
                out.println(line); 
        }
        rd.close(); 
} catch(Exception e) 
{
	response.setStatus(500);
}
%>
