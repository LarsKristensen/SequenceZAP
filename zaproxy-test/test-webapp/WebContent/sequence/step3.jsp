<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ page import="java.io.*" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<!--
    This file is part of the OWASP Zed Attack Proxy (ZAP) project (http://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)
    ZAP is an HTTP/HTTPS proxy for assessing web application security.
    
    Licensed under the Apache License, Version 2.0 (the "License"); 
    you may not use this file except in compliance with the License. 
    You may obtain a copy of the License at 
    
      http://www.apache.org/licenses/LICENSE-2.0 
      
    Unless required by applicable law or agreed to in writing, software 
    distributed under the License is distributed on an "AS IS" BASIS, 
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
    See the License for the specific language governing permissions and 
    limitations under the License. 
-->
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Step 1</title>
</head>
<body>
<%
   String type = request.getParameter( "messageType" );
   session.setAttribute( "type", type );
   
   //Save values in file
   String t = (String)session.getAttribute("type");
   String title = (String)session.getAttribute("title");
   String message = (String)session.getAttribute("message");
   String filePath = application.getRealPath("/") + "messages.txt";
   
   if(t != null && t.equals("user") && title != null && message != null) {
   
   		FileWriter filewriter = new FileWriter(filePath, true);
   		filewriter.write("<B>Title: </B>" + title + "<BR>");
   		filewriter.write("<B>Message: </B><BR>");
   		filewriter.write(message + "<BR><BR>");
   		filewriter.close();
   }
   
%>

	<h1>Step 3</h1>
	
	<% if(t != null && t.equals("user") && (title != null && message != null)){ %>
	<p>Your message has been posted.</p>
	<a href="final.jsp">Continue...</a>
	<% } else if(t != null && t.equals("admin")){ 
	%>
	<p>You cannot post admin messages.. sorry.</p>
	<a href="index.jsp">Go back</a>
	<%
	} else { 
	%>
	<p>Error in posting message, please start over.</p>
	<a href="index.jsp">Go back</a>
	<% } %>
</body>