from thrift.protocol.TBinaryProtocol import TBinaryProtocol
from thrift.protocol.TCompactProtocol import TCompactProtocol
from thrift.protocol.TJSONProtocol import TJSONProtocol
from thrift.transport import TTransport
from thrift_tools.thrift_struct import ThriftStruct
from thrift.Thrift import TMessageType, TType
import traceback

class ThriftEncoder(object):
	@classmethod
	def encode(cls, jsonObj):
		protocol = cls.str_to_proto(jsonObj['proto'])
		trans = TTransport.TMemoryBuffer()
		proto = protocol(trans)

		###TODO: header write first 

		proto.writeMessageBegin(jsonObj['method'], 
			cls.str_to_message_type(jsonObj['type']), jsonObj['seqid'])

		cls.write_struct(proto, jsonObj['args'])
		

		proto.writeMessageEnd()
		return trans.getvalue()

	@classmethod
	def write_struct(cls, proto, struct):
		fields = struct['fields']
		proto.writeStructBegin('')

		for field in fields:
			cls.write_field(proto, field)

		proto.writeFieldStop()
		proto.writeStructEnd()

	@classmethod
	def write_field(cls, proto, field, xtype=None):
		if xtype:
			ftype = xtype
			value = field
		else:
			try:
				ftype = cls.str_to_field_type(field['field_type'])
				value = field['value']
				proto.writeFieldBegin('', ftype, field['field_id'])
			except Exception as ex:
				print field
				print ex, traceback.format_exc()
		
		if ftype == TType.STRUCT:
			cls.write_struct(proto, value)
		elif ftype == TType.I32:
			proto.writeI32(value)
		elif ftype == TType.I64:
			proto.writeI64(value)
		elif ftype == TType.DOUBLE:
			proto.writeDouble(value)
		elif ftype == TType.STRING:
			proto.writeString(value)
		elif ftype == TType.LIST:
			etype = cls.str_to_field_type(value['etype'])
			values = value['values']
			proto.writeListBegin(etype, len(values))
			for val in values:
				if etype == TType.STRUCT:
					cls.write_struct(proto, val)
				else:
					cls.write_field(proto, val, etype)
			proto.writeListEnd()
		elif ftype == TType.MAP:
			ktype = cls.str_to_field_type(value['ktype'])
			vtype = cls.str_to_field_type(value['vtype'])
			values = value['values']
			proto.writeMapBegin(ktype, vtype, len(values))
			for k, v in values.iteritems():
				if ktype == TType.STRUCT:
					cls.write_struct(proto, k)
				else:
					cls.write_field(proto, k, ktype)
				if vtype == TType.STRUCT:
					cls.write_struct(proto, v)
				else:
					cls.write_field(proto, v, vtype)
				
			proto.writeMapEnd()
		elif ftype == TType.SET:
			etype = cls.str_to_field_type(value['etype'])
			values = value['values']
			proto.writeSetBegin(etype, len(values))
			for val in values:
				if etype == TType.STRUCT:
					cls.write_struct(proto, val)
				else:
					cls.write_field(proto, val, etype)
			proto.writeSetEnd()
		elif ftype == TType.BOOL:
			proto.writeBool(value)
		else:
			# for now, we ignore all other values
			raise ValueError('Type not impplemented: %s' % ftype)
		
		if not xtype:
			proto.writeFieldEnd()


	@staticmethod
	def str_to_proto(proto):
		proto = proto.lower()
		if proto == 'compact':
			return TCompactProtocol
		if proto == 'binary':
			return TBinaryProtocol
		if proto == 'json':
			return TJSONProtocol
		raise ValueError('Unknown protocol type: %s' % proto)

	@staticmethod
	def str_to_message_type(mtype):
		if mtype == 'call':
			return TMessageType.CALL
		elif mtype == 'reply':
			return TMessageType.REPLY
		elif mtype == 'exception':
			return TMessageType.EXCEPTION
		elif mtype == 'oneway':
			return TMessageType.ONEWAY
		else:
			raise ValueError('Unknown message type: %s' % mtype)

	@staticmethod
	def str_to_field_type(ftype):
		if ftype == 'stop':
			return TType.STOP
		elif ftype == 'void':
			return TType.VOID
		elif ftype == 'bool':
			return TType.BOOL
		elif ftype == 'byte':
			return TType.BYTE
		elif ftype == 'i08':
			return TType.I08
		elif ftype == 'double':
			return TType.DOUBLE
		elif ftype == 'i16':
			return TType.I16
		elif ftype == 'i32':
			return TType.I32
		elif ftype == 'i64':
			return TType.I64
		elif ftype == 'string':
			return TType.STRING
		elif ftype == 'utf7':
			return TType.UTF7
		elif ftype == 'struct':
			return TType.STRUCT
		elif ftype == 'map':
			return TType.MAP
		elif ftype == 'set':
			return TType.SET
		elif ftype == 'list':
			return TType.LIST
		elif ftype == 'utf8':
			return TType.UTF8
		elif ftype == 'utf16':
			return TType.UTF16
		else:
			raise ValueError('Unknown type: %s' % ftype)