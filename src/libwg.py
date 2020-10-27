# Icosa Consulting Inc. (c) 2020
# SDN library
# version: 1.0.0
#

"""
	Implements:
		Wireguard Wrapper C client library
			Icosa Consulting (c) 2020

		Wireguard embedded tools library
		https://github.com/WireGuard/wireguard-tools.git
		License: https://github.com/WireGuard/wireguard-tools/blob/master/COPYING

	Methods (libwg wrapper):
	wgclient new_client(char *iface)
	wgstatus wg_status(uint8_t *iface, char *error(out));
	wgstatus peer_status(uint8_t *iface, uint8_t *peerkey, char *error(out))

	Key Commands:
	void get_private_key64(char *privkey(out), char *error(out))
	int get_public_key64(uint8_t *privkey, char *pubkey(out), char *error(out))
	void wg_key_to_base64(wg_key_b64_string base64, const wg_key key)

	Interface Commands:
	int add_wg(uint8_t *iface, uint8_t  *privkey, uint8_t *peerkey, int port, char *error(out));
	int del_wg(uint8_t *iface, char *error(out));
	int get_wg(uint8_t *iface, wg_device *device, char *error(out));
	int set_wg(wg_device *device, char *error(out));

	Peer Commands:
	int add_client_peer(uint8_t *iface, uint8_t *peerkey, uint8_t *endpoint, uint8_t *allowedip[], int keepalive, char *error(out));
	int add_server_peer(uint8_t *iface, uint8_t *peerkey, uint8_t *allowedip[], char *error(out));
	int del_wg_peer(uint8_t *iface, uint8_t *peerkey, char *error(out))
"""
# Local Imports
from logger import SysLogger
from .shared import *

# System Imports
import sys
import logging
import typing
import ctypes, ctypes.util

# Text Coloring
try:
        from termcolor import colored
except:
        print("Please install pip3 termcolor first")
        sys.exit(1)


__version__ = "1.0.5"
__name__ = libwgso.__name__


# TODO: Move all Ctypes specific DLL code to separate library
# then subclass this

WG_KEY_LEN = 32 # Wireguard Key Size (bytes)
WG_KEY_LEN_B64 = 45 # Wireguard Key Size (base 64)

def libwrapper(lib, funcname, argtypes, restype = None):
	""" CDLL Function Wrapper """
	logging.debug("Init CDLL %s function %s", lib, funcname)

	func = lib.__getattr__(funcname)
	func.argtypes = argtypes

	# restype defaults to c_int
	if(restype):
		func.restype = restype
	return func

class WGClient(object):
	""" Implements Interface and Crypto Key functions """

	BUFFER_SIZE = (1024 + 1) # Default char_p buffer size

	class _wgstatus(ctypes.Structure):
		pass

	class _wgclient(ctypes.Structure):
		""" Our WG Client """
		class _wgdevice(ctypes.Structure):
			""" Defined in wireguard.h """
			class _wgpeer(ctypes.Structure):
				_fields_ = [
					('flags', ctypes.c_uint32),
					('public_key', ctypes.c_uint8 * WG_KEY_LEN),
					('private_key', ctypes.c_uint8 * WG_KEY_LEN),
					('wg_peer', ctypes.c_void_p)
				]

				def __str__(self):
					return '{0}'.format(type(self))

			_fields_ = [
				('name', ctypes.c_char * 16),
				('ifindex', ctypes.c_uint32),
				('flags', ctypes.c_uint32),
				('public_key', ctypes.c_uint8 * WG_KEY_LEN),
				('private_key', ctypes.c_uint8 * WG_KEY_LEN),
				('fwmark', ctypes.c_uint32),
				('listen_port', ctypes.c_uint16),
				('wg_peer', _wgpeer)
			]

			def __str__(self):
				return 'Device Name: {0} Listen Port: {1}'.format(self.name.decode('utf-8'), self.listen_port)
		_fields_ = [
			('id', ctypes.c_ulong),
			('memsize', ctypes.c_char * 16),
			('result', ctypes.c_int),
			('error', ctypes.c_char * 512),
			('device', _wgdevice)
		]

		def __init__(self, interface, libwg = None):
			"""
				Init a new WG client
				interface param is bytes
			"""
			if(libwg is not None):
				new_client = libwrapper(libwg, 'new_client', [ctypes.c_char_p], ctypes.POINTER(WGClient._wgclient))
				self = new_client(interface)

		def __str__(self):
			return 'ID: {0} MEM: {1} STATUS: {2}'.format(self.id, self.memsize.decode(), self.error.decode('utf-8'))

	def __init__(self, interface, loglevel=logging.INFO):
		""" Init library and device """

		# Init Logging
		self.logger = SysLogger(__name__, loglevel=loglevel).syslogger

		libname = 'shared/{0}.so'
		libwg = None
		self.libc = None
		self.interface = self._convert_str_bytes(interface)
		self._wgclientlib = None
		self._lasterror = 0

		# Aliases
		byte_t = ctypes.c_byte
		int_t = ctypes.c_int
		char_p = ctypes.c_char_p
		void_p = ctypes.c_void_p

		# Device Management
		self.new_client = None
		self.add_wg = None
		self.del_wg = None

		# Peer Management
		self.add_client_peer = None
		self.add_server_peer = None
		self.del_wg_peer = None

		# Key Management
		self.private_key = None
		self.pubic_key = None
		self.key_base64 = None

		try:
			# Shared Library DLL
			libwg = libwgso.dll()

			# Load standard C library
			self.libc = ctypes.CDLL(ctypes.util.find_library('c'))
			self.libc.free.argtypes=[void_p]

			# Set methods from libwg
			# Params are input unless otherwise noted
			self.new_client = self._wrapper(libwg, 'new_client', [char_p], ctypes.POINTER(self._wgclient))

			# void get_private_key64(char *privkey(out), char *error(out))
			self.private_key = self._wrapper(libwg, 'get_private_key64', [char_p, char_p])

			# int get_public_key64(uint8_t *privkey, char *pubkey(out), char *error(out))
			self.public_key = self._wrapper(libwg, 'get_public_key64', [char_p, char_p, char_p])

			# int add_wg(uint8_t *iface, uint8_t *privkey, int port, char *error(out))
			self.add_wg = self._wrapper(libwg, 'add_wg', [char_p, char_p, int_t, char_p])

			# int del_wg(uint8_t *iface, char *error(out))
			self.del_wg = self._wrapper(libwg, 'del_wg', [char_p, char_p])

			# int add_client_peer(uint8_t *iface, uint8_t *peerkey, uint8_t *endpoint, uint8_t *allowedip[], int keepalive, char *error(out));
			self.add_client_peer = self._wrapper(libwg, 'add_client_peer', [char_p, char_p, char_p, char_p, int_t, char_p])

			# int add_server_peer(uint8_t *iface, uint8_t *peerkey, uint8_t *allowedip[], char *error(out));
			self.add_server_peer = self._wrapper(libwg, 'add_server_peer', [char_p, char_p, char_p, char_p])

			# int del_wg_peer(uint8_t *iface, uint8_t *peerkey, char *error(out))
			self.del_wg_peer = self._wrapper(libwg, 'del_wg_peer', [char_p, char_p, char_p])

			# void wg_key_to_base64(wg_key_b64_string base64(out), const wg_key key)
			self.key_base64 = self._wrapper(libwg, 'wg_key_to_base64', [void_p, void_p])

			self._wgclientlib = self.new_client(self.interface)
			#self._wgclientlib = self._wgclient(self.interface, libwg)

			self.logger.info('WGClient %s', self._wgclientlib.contents)

		# Any errors should terminate the library
		except Exception as _:
			self.logger.critical("Initialization error, DLL Load returned %d. Error: %s", ctypes.get_errno(), _)
			sys.exit(-1)

	def __del__(self):
		""" Clean up on GC """
		#if (self.wgclient):
		#	self.libc.free(self.wgclient)

	@staticmethod
	def _wrapper(lib, funcname, argtypes, restype = None):
		return libwrapper(lib, funcname, argtypes, restype)

	@staticmethod
	def _convert_str_bytes(input):
		""" Check a string and convert to bytes if needed """
		if (type(input) != bytes):
			return str.encode(input, 'utf-8')
		else:
			return input

	@staticmethod
	def _convert_ptr_bytes(pointer):
		""" Converts a string pointer to byte array """
		result = b''
		result = bytes(ctypes.string_at(pointer))
		return result

	@staticmethod
	def _create_buffer(buffer_size = BUFFER_SIZE):
		"""
			Create a byte array for buffering
			buffer size: 1024 + 1
		"""
		buffer = (ctypes.c_char * int(buffer_size))()
		try:
			ctypes.memset(ctypes.addressof(buffer), 0, ctypes.sizeof(buffer))
		except:
			self.logger.error(colored('Failed to create buffer with length %d', 'red') ,buffer_size)

		return buffer

	def _log_result(self, result, message):
		if (type(message) == bytes):
			message = message.decode()

		if(result != 0):
			self.logger.error('%s %s',__name__, message)
		else:
			self.logger.info('%s %s',__name__, message)


	def _convert_str_ptr(self, string_in):
		""" Convert string to char pointer """

		convert = b''
		convert = self._convert_str_bytes(string_in)
		return ctypes.byref(ctypes.cast(convert, ctypes.c_byte))

	@property
	def lasterror(self):
		""" Get the last result code """
		return self._lasterror

	@lasterror.setter
	def lasterror(self, value):
		""" Set the last result code """
		self._lasterror = value


	@property
	def wgclient(self):
		return self._wgclientlib

	@property
	def wgdevice(self):
		"""
			Returns the WG Device struct
			Each device object is tied to the instance of the DLL.
			So multiple calls here will return the same device object.
		"""

		device = self.wgclient.contents
		self.lasterror = device.result

		#self.logger.debug('WGClient %s', device)

		return device

	@property
	def wgpubkey(self):
		"""
			Returns the WG interface local public key
		"""
		key = self._create_buffer(WG_KEY_LEN_B64 + 1)

		pubkey = self._convert_ptr_bytes(self.wgdevice.device.public_key)
		self.key_base64(key, pubkey)
		return self._convert_ptr_bytes(key).decode()

	def get_privatekey(self):
		""" Generate a Wireguard Base64 Private Key"""
		result = None
		privkey = None

		error_text = self._create_buffer(512)
		key = self._create_buffer(WG_KEY_LEN_B64 + 1)

		#key = (ctypes.c_ubyte * len(key)).from_buffer_copy(key)
		result = self.private_key(key, error_text)
		error_text = self._convert_ptr_bytes(error_text).decode()

		if(result == 0):
			privkey = ctypes.c_char_p(ctypes.addressof(key)).value
		else:
			self._log_result(result, error_text)

		self.lasterror = result
		return privkey

	def get_publickey(self, privkey):
		"""
			Gets the Base64 Public Key from Private Key
			Key MUST be in Wireguard Base64 encoding when passed in.
		"""

		result = None
		pubkey = None

		error_text = self._create_buffer(512)
		key = self._create_buffer(WG_KEY_LEN_B64 + 1)

		#privkey = ctypes.byref(privkey)
		#privkey = (ctypes.c_char * len(privkey)).from_buffer(privkey).value
		#privkey = ctypes.c_char_p(ctypes.addressof(privkey)).value

		result = self.public_key(privkey, key, error_text)
		error_text = self._convert_ptr_bytes(error_text).decode()

		if(result == 0):
			pubkey = ctypes.c_char_p(ctypes.addressof(key)).value
		else:
			self._log_result(result, error_text)

		self.lasterror = result
		return (pubkey, result)

	def add_interface(self, privkey, port):
		""" Add Wireguard interface """

		result = 0
		error_text = self._create_buffer(512)
		privkey = self._convert_str_bytes(privkey)

		result = self.add_wg(self.interface, privkey, int(port), error_text)
		error_text = self._convert_ptr_bytes(error_text).decode()

		self.lasterror = result
		self._log_result(result, error_text)
		return (error_text, result)

	def del_interface(self, interface):
		""" Delete Wireguard interface """

		result = 0
		error_text = self._create_buffer(512)
		interface = self._convert_str_bytes(interface)

		result = self.del_wg(interface)
		error_text = self._convert_ptr_bytes(error_text).decode()

		self.lasterror = result
		self._log_result(result, error_text)
		return (error_text, result)

	def client_peer(self, peerkey, endpoint, allowedip=None, keepalive=15):
		""" Add Wireguard Hub device peer on client"""

		result = 0
		error_text = self._create_buffer(1024)

		if ((endpoint is None) or (endpoint == '')):
			return ('Endpoint settings required to peer', -1)

		if ((allowedip is None) or (allowedip == '')):
			allowedip='::/0, 0.0.0.0/0'

		peerkey = self._convert_str_bytes(peerkey)
		endpoint = self._convert_str_bytes(endpoint)
		allowedip = self._convert_str_bytes(allowedip)

		result = self.add_client_peer(self.interface, peerkey, endpoint, allowedip, int(keepalive), error_text)
		error_text = self._convert_ptr_bytes(error_text).decode()

		self.lasterror = result
		self._log_result(result, error_text)
		return (error_text, result)

	def server_peer(self, peerkey, allowedip=None):
		""" Add Wireguard device peer on VPN Hub """

		result = 0
		error_text = self._create_buffer(1024)

		if ((allowedip is None) or (allowedip == '')):
			allowedip='::/0, 0.0.0.0/0'

		peerkey = self._convert_str_bytes(peerkey)
		allowedip = self._convert_str_bytes(allowedip)

		result = self.add_server_peer(self.interface, peerkey, allowedip, error_text)
		error_text = self._convert_ptr_bytes(error_text).decode()

		self.lasterror = result
		self._log_result(result, error_text)
		return (error_text, result)

	def del_peer(self, peerkey):
		""" Delete Wireguard device peer """

		result = 0
		error_text = self._create_buffer(1024)
		peerkey = self._convert_str_bytes(peerkey)

		result = self.del_wg_peer(self.interface, peerkey, error_text)
		error_text = self._convert_ptr_bytes(error_text).decode()

		self.lasterror = result
		self._log_result(result, error_text)
		return (error_text, result)
