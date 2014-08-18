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
<title>OWASP ZAP Test WebApp</title>
</head>
<body>
<%
   String f3 = request.getParameter( "field3" );
   session.setAttribute( "field3", f3 );
%>
	<h1>Message board:</h1>
	<p>
	<%
	
			String filePath = application.getRealPath("/") + "messages.txt";
			
			File file = new File(filePath);
			
			if(file.exists()){
			
            	BufferedReader reader = new BufferedReader(new FileReader(file));
            	StringBuilder sb = new StringBuilder();
            	String line;

            	while((line = reader.readLine())!= null){
                	sb.append(line+"\n");
            	}	
            	out.println(sb.toString());
            }
       %>
	</p>
</body>
</html>