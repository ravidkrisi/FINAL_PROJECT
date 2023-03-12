import unittest
from client import *
from dhcp import *
from dns import *
from web_server import *
from storage_server import *

class TestProject(unittest.TestCase):
    start_server()
    start_dhcp_server()



