package org.zaproxy.zap.extension.sequence;

import java.util.ArrayList;
import java.util.List;

import javax.swing.ImageIcon;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.ScannerHook;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.script.SequenceScript;

public class ExtensionSequence extends ExtensionAdaptor implements ScannerHook {

	private ExtensionScript extScript;
	public static final Logger logger = Logger.getLogger(ExtensionSequence.class);
	public static final ImageIcon ICON = new ImageIcon(ExtensionSequence.class.getResource("/org/zaproxy/zap/extension/sequence/resources/icons/script-sequence.png"));
	public static final String TYPE_SEQUENCE = "sequence";

	private List<ScriptWrapper> enabledScripts = null;

	public void setDirectScanScript(ScriptWrapper script) {
		enabledScripts = new ArrayList<ScriptWrapper>();
		enabledScripts.add(script);
	}

	public ExtensionSequence() {
		super("ExtensionSequence");
		this.setOrder(29);
	}

	@Override
	public String getAuthor() {
		return Constant.ZAP_TEAM;
	}

	private ExtensionScript getExtScript() {
		if(extScript == null) {
			extScript = (ExtensionScript) Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
		}
		return extScript;
	}

	@Override
	public void hook(ExtensionHook extensionhook) {
		super.hook(extensionhook);
		ScriptType type = new ScriptType(TYPE_SEQUENCE, "script.type.sequence", ICON, true);
		getExtScript().registerScriptType(type);
		extensionhook.getHookMenu().addPopupMenuItem(new SequencePopupMenuItem(this));
		extensionhook.addScannerHook(this);
	}

	@Override
	public void beforeScan(HttpMessage msg) {	
		List<ScriptWrapper> sequences = getEnabledSequenceScripts();
		for(ScriptWrapper wrapper: sequences) {
			try {
				SequenceScript seqScr = getExtScript().getInterface(wrapper, SequenceScript.class); 
				if(seqScr != null) {
					if(seqScr.isPartOfSequence(msg)) {
						HttpMessage newMsg = seqScr.runSequence(msg);
						msg.setRequestHeader(newMsg.getRequestHeader());
						msg.setRequestBody(newMsg.getRequestBody());
						break;
					}
				}
			} catch (Exception e) {
				logger.error(e.getMessage(), e);
			}
		}
	}


	private List<ScriptWrapper> getEnabledSequenceScripts() {
		if(enabledScripts == null) {
			enabledScripts = new ArrayList<ScriptWrapper>();
			List<ScriptWrapper> temp = getExtScript().getScripts(TYPE_SEQUENCE);

			for(ScriptWrapper wrapper : temp) {
				if(wrapper.isEnabled()) {
					enabledScripts.add(wrapper);
				}
			}
		}
		return enabledScripts;
	}

	@Override
	public void scannerComplete() {
		this.enabledScripts = null;
	}
}