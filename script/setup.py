# setup.py
from distutils.core import setup
import py2exe
import sys

sys.argv.append('py2exe')

py2exe_options = {
    "compressed": 1,
    "optimize": 2,
    #"bundle_files": 1,
    "includes":["sip", "PyQt4.QtCore", "PyQt4.QtGui"],
    #, "ascii":0
    "dist_dir":"../bin/win32/"
}

setup(
    windows = [{"script" : "./MainWindow.py"}],
    zipfile = None,
   # name = "NcgPcap",
    options = {'py2exe':py2exe_options}
)
