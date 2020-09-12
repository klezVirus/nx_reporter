import sys
import os, sys
from configurer import nx_config

if not sys.argv[1]:
	path = str(os.getcwd()) + "nx_reporter"
else:
	path = sys.argv[1] + "nx_reporter"

config = nx_config()



config.set("GLOBAL_DIRS","ROOT_DIR", path)
config.save_config()

