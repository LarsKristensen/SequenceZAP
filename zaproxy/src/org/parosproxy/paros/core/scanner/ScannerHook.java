package org.parosproxy.paros.core.scanner;

import org.parosproxy.paros.network.HttpMessage;

//SEQ: Added this interface
public interface ScannerHook {
	
	void scannerComplete();
	
	void beforeScan(HttpMessage msg);

}
