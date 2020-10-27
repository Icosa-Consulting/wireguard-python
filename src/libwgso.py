# Wirguard Wrapper Library
# (c) 2020 Icosa Consulting Inc.
#
import os,sys,time
import ctypes, ctypes.util

__name__ = 'libwg.so'

class libwgso():
	""" Wireguard Wrapper shared library """

	@staticmethod
	def dll():
		libname = '{0}'
		libdll = None

		path = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))
		libfile = os.path.join(path, libname.format(__name__))
		if (os.path.isfile(libfile)):
			libdll = ctypes.CDLL(libfile, use_errno=True)
		else:
			libdll = ctypes.CDLL(ctypes.util.find_library(libname.format('libwg')), use_errno=True)

		return libdll
