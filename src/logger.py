# Wrapper Library
# (c) 2020 Icosa Consulting Inc.

"""
        Logging Base Class
        Initializes:
               Syslog

"""

# System Imports
import logging
import logging.config
from logging.handlers import SysLogHandler

class SysLogger(object):
	""" Global System Logger Module """

	def __init__(self, name=__name__, loglevel=logging.INFO, address=None, format=None):
		""" Initialize logging handler """

		if address is None:
			address='/dev/log'

		if format is None:
			format="%(module)-15s : %(levelname)s - %(message)s"

		syslogfmt = logging.Formatter(format)
		logger = logging.getLogger(name)

		if (loglevel != logger.level):
			logger.level = loglevel

		handler = SysLogHandler(address=address)
		handler.setFormatter(syslogfmt)
		handler.setLevel(loglevel)

		# Only add the handler once per instance
		if (logger.handlers.count(handler) == 0):
			logger.addHandler(handler)

		self._logger = logger
		self._handler = handler
		logger.info('Logger %s Handlers %s', logger.name, handler)

	@property
	def syslogger(self):
		return self._logger

	@property
	def syshandler(self):
		return self._handler
