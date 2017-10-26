
from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IContextMenuFactory, IHttpListener

# Java imports
from javax.swing import JMenuItem
from java.util import ArrayList

import traceback, json

from thrift_tools.thrift_message import ThriftMessage
from ThriftEncoder import ThriftEncoder

# Menu items
menuItems = {
	False: "Turn Thrift active detection on",
	True:  "Turn Thrift active detection off"
}

# Global Switch
_forceThrift = False
DEBUG = True

def format_msg(msg, indent=4, tjson=True):
	if tjson:
		outputstr = json.dumps(msg.as_dict, indent=indent, ensure_ascii=False) + '\n'
	else:
		indents = ' ' * indent if indent else ''
		header_line = '%sheader: %s,\n' % (indents, msg.header)
		fields_line = '%sfields: %s\n' % (indents, msg.args)
		outputstr = 'method: %s, type: %s, seqid: %d,\n%s%s' % (
			msg.method, msg.type, msg.seqid, header_line, fields_line)

	return outputstr

class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IContextMenuFactory, IHttpListener):
	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()

		callbacks.setExtensionName('Thrift Decoder')
		callbacks.registerMessageEditorTabFactory(self)
		callbacks.registerContextMenuFactory(self)
		callbacks.registerHttpListener(self)
		
		return

	def processResponse(self, toolFlag, messageInfo):
		try:
			response = messageInfo.getResponse()
			responseStr = self._helpers.bytesToString(response)
			responseInfo = self._helpers.analyzeResponse(response)
			body = responseStr[responseInfo.getBodyOffset():]
			headers = responseInfo.getHeaders()
			for (i, header) in enumerate(headers):
				if header.lower() == 'content-type: application/x-thrift':
					break
			else:
				return

			msg, msglen = ThriftMessage.read(body, read_values=True)
			response = self._helpers.buildHttpMessage(headers, 
				self._helpers.stringToBytes(format_msg(msg)))
			messageInfo.setResponse(response)
		except Exception as ex:
			print "problem parsing data in processResponse"
			if DEBUG:
				print ex, traceback.format_exc()

	def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
		if toolFlag & self._callbacks.TOOL_REPEATER:
			return
		if toolFlag & self._callbacks.TOOL_PROXY:
			return
		if not messageIsRequest:
			return self.processResponse(toolFlag, messageInfo)
		try:
			request = messageInfo.getRequest()
			requestInfo = self._helpers.analyzeRequest(messageInfo)
			headers = requestInfo.getHeaders()
			msgBody = self._helpers.bytesToString(request[requestInfo.getBodyOffset():])

			for (i, header) in enumerate(headers):
				if header.lower() == 'content-type: application/x-thrift-decoded':
					headers[i] = "Content-Type: application/x-thrift"
					break
			else:
				return

			msgBody = ThriftEncoder.encode(json.loads(msgBody))
			request = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(msgBody))
			messageInfo.setRequest(request)
		except Exception as ex:
			print "problem parsing data in processHttpMessage"
			if DEBUG:
				print ex, traceback.format_exc()

	def createNewInstance(self, controller, editable): 
		return thriftDecoderTab(self, controller, editable)

	def createMenuItems(self, IContextMenuInvocation):
		global _forceThrift
		menuItemList = ArrayList()
		menuItemList.add(JMenuItem(menuItems[_forceThrift], actionPerformed = self.onClick))

		return menuItemList

	def onClick(self, event):
		global _forceThrift
		_forceThrift = not _forceThrift
		
class thriftDecoderTab(IMessageEditorTab):
	def __init__(self, extender, controller, editable):
		self._extender = extender
		self._helpers = extender._helpers
		self._editable = editable
		
		self._txtInput = extender._callbacks.createTextEditor()
		self._txtInput.setEditable(editable)

		self._thriftMagicMark = ["\x80\x01"]
		
		return
		
	def getTabCaption(self):
		return "Thrift Decoder"
		
	def getUiComponent(self):
		return self._txtInput.getComponent()
		
	def isEnabled(self, content, isRequest):
		global _forceThrift

		if isRequest:
			r = self._helpers.analyzeRequest(content)
		else:
			r = self._helpers.analyzeResponse(content)

		msg = content[r.getBodyOffset():].tostring()

		if _forceThrift and len(msg) > 2 and msg[:2] in self._thriftMagicMark:
			print "Forcing Thrift"
			return True
			
		for header in r.getHeaders():
			if header.lower().startswith("content-type:"):
				content_type = header.split(":")[1].lower()
				if content_type.find("application/x-thrift") > 0 or content_type.find("text/x-thrift") > 0:
					return True
				else:
					return False

		return False
		
	def setMessage(self, content, isRequest):
		if content is None:
			self._txtInput.setText(None)
			self._txtInput.setEditable(False)
		else:
			if isRequest:
				r = self._helpers.analyzeRequest(content)
			else:
				r = self._helpers.analyzeResponse(content)
			
			data = content[r.getBodyOffset():].tostring()

			try:
				msg, msglen = ThriftMessage.read(data, read_values=True)
			except Exception as ex:
				print "problem parsing data in setMessage"
				if DEBUG:
					print ex, traceback.format_exc()

			self._txtInput.setText(format_msg(msg))
			self._txtInput.setEditable(self._editable)
			
		self._currentMessage = content

	def getMessage(self): 
		if self._txtInput.isTextModified():
			try:
				text = self._helpers.bytesToString(self._txtInput.getText())
				data = ThriftEncoder.encode(json.loads(text))
			except Exception as ex:
				print "problem parsing data in getMessage"
				if DEBUG:
					print ex, traceback.format_exc()
				data = self._helpers.bytesToString(self._txtInput.getText())
				
			r = self._helpers.analyzeRequest(self._currentMessage)
				
			return self._helpers.buildHttpMessage(r.getHeaders(), self._helpers.stringToBytes(data))
		else:
			return self._currentMessage
		
	def isModified(self):
		return self._txtInput.isTextModified()
		
	def getSelectedData(self):
		return self._txtInput.getSelectedText()
