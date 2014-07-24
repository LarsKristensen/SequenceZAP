package org.zaproxy.zap.extension.script;

import org.parosproxy.paros.network.HttpMessage;

public interface SequenceScript {
	
	HttpMessage runSequence(HttpMessage msg);
	
	boolean isPartOfSequence(HttpMessage msg);
	
	void runSequence();

}
