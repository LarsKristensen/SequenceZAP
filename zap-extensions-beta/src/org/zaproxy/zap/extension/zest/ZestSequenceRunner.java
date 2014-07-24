package org.zaproxy.zap.extension.zest;

import java.io.IOException;
import java.net.HttpCookie;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.Cookie;
import org.apache.commons.lang.ArrayUtils;
import org.apache.log4j.Logger;
import org.mozilla.zest.core.v1.ZestActionFailException;
import org.mozilla.zest.core.v1.ZestAssertFailException;
import org.mozilla.zest.core.v1.ZestAssignFailException;
import org.mozilla.zest.core.v1.ZestClientFailException;
import org.mozilla.zest.core.v1.ZestInvalidCommonTestException;
import org.mozilla.zest.core.v1.ZestRequest;
import org.mozilla.zest.core.v1.ZestResponse;
import org.mozilla.zest.core.v1.ZestScript;
import org.mozilla.zest.core.v1.ZestStatement;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.script.SequenceScript;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.session.SessionManagementMethod;

public class ZestSequenceRunner extends ZestZapRunner implements SequenceScript {

	private ZestScriptWrapper script = null; 
	private ExtensionActiveScan extAscan = null;
	private ExtensionHistory extHistory = null;
	private static final Logger logger = Logger.getLogger(ZestSequenceRunner.class);
	private static final Map<String, String> EmptyParams = new HashMap<String, String>();
	private static Map<String, ArrayList<HttpCookie>> TempCookies = new HashMap<String, ArrayList<HttpCookie>>();

	//Note: These were copy-pasted from the session extension.
	private static final String[] SESSION_IDENTIFIERS = { "asp.net_sessionid", "aspsessionid", "siteserver", "cfid",
		"cftoken", "jsessionid", "phpsessid", "sessid", "sid", "viewstate", "zenid" };
	private static final String[] COOKIE_IDENTIFIERS = { "path", "domain", "expires", "secure", "httponly" };

	private ExtensionActiveScan getActiveScanner() {
		if(extAscan == null) {
			extAscan = (ExtensionActiveScan) Control.getSingleton().getExtensionLoader().getExtension(ExtensionActiveScan.class);
		}
		return extAscan;
	}

	private ExtensionHistory getHistory() {
		if(extHistory == null) {
			extHistory = (ExtensionHistory) Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class);
		}
		return extHistory;
	}
	
	public ZestSequenceRunner(ExtensionZest extension, ZestScriptWrapper wrapper) {
		super(extension, wrapper);
		this.script = wrapper;
		this.setStopOnAssertFail(false);
	}

	@Override
	public void runSequence() {
		SiteNode fakeRoot = new SiteNode(null, 11, "");
		SiteNode fakeDirectory = new SiteNode(null, 11, "");

		for(ZestStatement stmt : script.getZestScript().getStatements()) {
			try {
				if(stmt.getElementType().equals("ZestRequest")) {
					ZestRequest req = (ZestRequest)stmt;
					HttpMessage msg = ZestZapUtils.toHttpMessage(req, req.getResponse());
					SiteNode node = messageToSiteNode(msg);

					if(node != null) {
						fakeDirectory.add(node);
					}
				}
			}
			catch(Exception e) {
				logger.error("Cannot create sitenode.");
			}
		}
		fakeRoot.add(fakeDirectory);
		getActiveScanner().startScan(fakeRoot);
	}

	@Override
	public HttpMessage runSequence(HttpMessage msg) {
		HttpMessage newMsq = msg.cloneAll();
		try	{
			msg = getMatchingMessageFromScript(msg);
			ZestScript scr = getSubScript(msg);
			this.run(scr, EmptyParams);

			List<HttpCookie> cookies = getCookies(scr, this.getLastRequest(), this.getLastResponse());	
			String reqBody = msg.getRequestBody().toString();
			reqBody = this.replaceVariablesInString(reqBody, false);
			newMsq.setRequestBody(reqBody);
			reqBody = newMsq.getRequestBody().toString();
		
			newMsq.setCookies(cookies);
			newMsq.getRequestHeader().setContentLength(newMsq.getRequestBody().length());
		}
		catch(Exception e) {
			logger.error("Error running Sequence script: " + e.getMessage());
		}
		return newMsq;
	}

	@Override
	public ZestResponse runStatement(ZestScript script, ZestStatement stmt,
			ZestResponse lastResponse) throws ZestAssertFailException,
			ZestActionFailException, ZestInvalidCommonTestException,
			IOException, ZestAssignFailException, ZestClientFailException {
		ZestResponse response = super.runStatement(script, stmt, lastResponse);
		if(stmt.getElementType().equals("ZestRequest")) {
			ZestRequest request = (ZestRequest)stmt;
			setTempCookies(script, request, response);
		}
		return response;
	}
	
	@Override
	public boolean isPartOfSequence(HttpMessage msg) {
		for(ZestStatement stmt : script.getZestScript().getStatements()) {
			if(isSameRequest(msg, stmt)) {
				return true;
			}
		}
		return false;
	}	

	private boolean isSameRequest(HttpMessage msg, ZestStatement stmt) {
		try {
			if(stmt.getElementType().equals("ZestRequest")) {
				ZestRequest msgzest = ZestZapUtils.toZestRequest(msg, true);
				ZestRequest req = (ZestRequest)stmt;

				if(msgzest.getUrl().equals(req.getUrl())) {
					if(msgzest.getMethod().equals(req.getMethod())) {
						return true;
					}
				}
			}
		}
		catch(Exception e) {
			logger.debug("Exception in ZestSequenceRunner isSameRequest:" + e.getMessage());
		}
		return false;
	}

	private HttpMessage getMatchingMessageFromScript(HttpMessage msg) {
		try {
			for(ZestStatement stmt : this.script.getZestScript().getStatements()) {
				if(isSameRequest(msg, stmt)) {
					ZestRequest req = (ZestRequest)stmt;
					return ZestZapUtils.toHttpMessage(req, req.getResponse());
				}
			}
		}
		catch(Exception e) {
			logger.error("Error in getMatchingMessageFromScript: " + e.getMessage());
		}
		return null;
	}
	
	private SiteNode messageToSiteNode(HttpMessage msg) {
		SiteNode temp = null;
		try {
			temp = new SiteNode(null, 11, "");

			HistoryReference ref = new HistoryReference(getHistory().getModel().getSession(), HistoryReference.TYPE_RESERVED_11, msg);
			getHistory().addHistory(ref);
			temp.setHistoryReference(ref);
		}
		catch(Exception e) {
			logger.debug("Exception in ZestSequenceRunner messageToSiteNode:" + e.getMessage());
		}
		return temp;
	}

	private void AddOrReplaceCookie(String session, HttpCookie cookie) {
		if(!TempCookies.containsKey(session)) {
			TempCookies.put(session, new ArrayList<HttpCookie>());
		}

		ArrayList<HttpCookie> list = TempCookies.get(session);

		for(int i = 0; i < list.size(); i++) {
			HttpCookie listCookie = list.get(i);
			if(listCookie.getName().equals(cookie.getName())) {
				list.remove(i);
				i--;
			}
		}
		list.add(cookie);
		TempCookies.put(session, list);
	}

	private HttpCookie getSessionCookie(ZestRequest req, ZestResponse resp) {
		if(req == null || resp == null) {
			return null;
		}
		try {
			HttpMessage msg = ZestZapUtils.toHttpMessage(req, resp);

			Context context = null;
			Session session = Model.getSingleton().getSession();
			List<Context> contexts = session.getContextsForUrl(req.getUrl().toString());

			if(contexts.size() > 0) {
				context = contexts.get(0);
			}
			else {
				context = session.getNewContext();
			}

			if(context != null) {
				SessionManagementMethod meth = context.getSessionManagementMethod();
				if(meth != null) {
					Cookie[] sessioncookies = meth.extractWebSession(msg).getHttpState().getCookies();
					for(Cookie cookie : sessioncookies) {
						String cookieName = cookie.getName().toLowerCase();
						for(String token :  SESSION_IDENTIFIERS) {
							if(cookieName.contains(token)) {
								HttpCookie sessCookie = new HttpCookie(cookie.getName(), cookie.getValue());
								return sessCookie;
							}
						}
					}
				}
			}
		}catch(Exception e)
		{
			logger.debug("Exception in ZestSequenceRunner getSessionCookie:" + e.getMessage());
		}
		return null;
	}

	private List<HttpCookie> getCookies(ZestScript finishedScript, ZestRequest lastReq, ZestResponse lastResp) {
		ArrayList<HttpCookie> cookies = new ArrayList<HttpCookie>();

		try {
			HttpCookie sessCookie = getSessionCookie(lastReq, lastResp);

			if(sessCookie == null) {
				return cookies;
			}
			
			sessCookie.setPath("/");
			sessCookie.setVersion(0);
			cookies.add(sessCookie);
			if(TempCookies.containsKey(sessCookie.getValue())) {
				List<HttpCookie> tem = TempCookies.get(sessCookie.getValue());

				for(HttpCookie cookie : tem) {
					cookie.setPath("/");
					cookie.setVersion(0);
					cookies.add(cookie);
				}
			}
		}
		catch(Exception e) {
			logger.error("Exception in ZestSequenceRunner getCookies() : " + e.getMessage());
		}

		return cookies;
	}

	private void setTempCookies(ZestScript script, ZestRequest request, ZestResponse response) {
		try {
			HttpCookie sessCookie = getSessionCookie(request, response);
			if(sessCookie != null) {
				String headers = response.getHeaders();
				if(headers.toLowerCase().contains("set-cookie:")) {
					String[] lines = headers.split("\r\n");
					for (String line : lines) {
						if (line.toLowerCase().startsWith("set-cookie:")) {
							String values = line.split(":")[1];
							String[] temp = values.split(";");
							for(int i = 0; i <temp.length; i++) {
								String[] field = temp[i].split("=");

								String name = field[0].toLowerCase().trim();
								boolean skipCookie = false;
								for(String identifier : (String[])ArrayUtils.addAll(SESSION_IDENTIFIERS, COOKIE_IDENTIFIERS)) {
									if(name.contains(identifier)) {
										skipCookie = true;
									}
								}

								if(!skipCookie) {
									HttpCookie cookie = new HttpCookie(field[0], field[1]);
									AddOrReplaceCookie(sessCookie.getValue(), cookie);
								}
							}
						}
					}
				}
			}
		}
		catch(Exception e) {
			logger.error("Exception in ZestSequenceRunner setTempCookies: " + e.getMessage());
		}
	}

	private ZestScript getSubScript(HttpMessage msg) {
		ZestScript scr = new ZestScript();
		ArrayList<ZestStatement> stmts = new ArrayList<ZestStatement>();

		for(ZestStatement stmt : this.script.getZestScript().getStatements()) {
			if(isSameRequest(msg, stmt)) {
				break;
			}
			stmts.add(stmt);
		}
		scr.setStatements(stmts);

		return scr;
	}
}