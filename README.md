SequenceZAP
===========

A mechanism for scanning a sequence of Http Requests, for Zed Attack Proxy (ZAP).

To get it to work, you need the ZAP source code, available at:

http://sourceforge.net/projects/zaproxy/files/workspace/workspace-zap.zip

Once the source code is extracted, copy the files from this repository to the workspace. Then open build.xml in the main branch, and run the “copy-jars-to-extensions” ant command (Note: we use Eclipse as IDE, and sometimes we need to do a Clean Project after this step). When the build is finished, open build.xml from the beta branch, and run the “deploy-sequence” ant command. This will also deploy zest. Now run ZAP, and you should be able to create, run and scan sequence scripts!
