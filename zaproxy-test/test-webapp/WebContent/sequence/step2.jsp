<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
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
   String f1 = request.getParameter( "title" );
   session.setAttribute( "title", f1 );
   
   String f2 = request.getParameter( "message" );
   session.setAttribute( "message", f2 );
%>
	<h1>Step 2</h1>
	<FORM METHOD=POST ACTION="step3.jsp">
		Message Type: 
		<select name="messageType">
			<option value="admin">Admin post</option>
			<option value="user">User post</option>
		</select>
	<P><INPUT TYPE=SUBMIT>
	</FORM>
</body>