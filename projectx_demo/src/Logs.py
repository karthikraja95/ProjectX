from WindowsEvents import WindowsEvents
from WebServer import WebServer
from Database import DatabaseLogs

class Logs:	

	def __init__(self, elkIP):
		
		self.WindowsEvents = WindowsEvents(elkIP)
		self.WebLogs = WebServer(elkIP)
		self.DatabaseLogs = DatabaseLogs(elkIP)		

