#!/usr/bin/env python3
# Icosa Consulting Inc. (c) 2020
# Wireguard library test script
#
#
#
#######################
import sys
import logging
# Hash / Crypto Imports
import hashlib

# Test Library (Change to your make location)
from dist.libwg import WGClient
from dist.logger import SysLogger

class TestClient(WGClient):
	"""
		Wireguard Client Implementation
	"""

	def __init__(self, interface, loglevel=logging.INFO):
		""" Initialization """

		self.logger = SysLogger(__name__, loglevel = loglevel).syslogger
		super().__init__(interface, loglevel)

if __name__ == '__main__':
	# Set Logging Level Globally
	fmt = '%(asctime)s | %(threadName)11s | %(name)s | %(levelname)s - %(message)s'
	logging.basicConfig(format=fmt, level=logging.INFO)

	test = TestClient('wg0')
	#print(dir(test.wg.wgdevice.device.public_key))
	test.logger.info("Wireguard device {0} has port {1:d}".format(test.wgdevice.device.name, test.wgdevice.device.listen_port))

	priv = test.get_privatekey()
	test.logger.info("Generated Private key %s", priv)
	pub = test.get_publickey(priv)
	test.logger.info("Generated Public key %s", pub)

	device = test.wgdevice.device
	test.add_interface(priv, 51210)
	test.logger.error("Last Error %s", test.lasterror)

	test.client_peer("dX5oI5piTjP9x/sV+mVfJHxWd3noQuoQeheaV06j3lE=", "127.0.0.1:53",'0.0.0.0/0,::/0', 15)
	test.logger.info(test.wgpubkey)

	test.del_peer("dX5oI5piTjP9x/sV+mVfJHxWd3noQuoQeheaV06j3lE=")

	print("These messages are also in the /var/log/syslog on Debian")
