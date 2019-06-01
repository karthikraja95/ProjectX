#Importing Necessary Libraries
from Model import Model
from Logs import Logs
from datetime import datetime, date, time, timedelta
import configparser
import time as t
import threading
from threading import Thread
import warnings
from Mail import Mail
import smtplib
from email.message import EmailMessage
warnings.filterwarnings("ignore", category=DeprecationWarning)


def SendNotification(config, subject, message):
	'''
	DO NOT USE INSIDE TD NETWORK AS OF AUGUST 17 2018, OUTBOUND SMTP REQUESTS ARE BLOCKED.
	'''
	
	SERVER = "smtp.gmail.com"
	user_name = config['mail']['user']
	password = config['mail']['pw']
	target_email ='ashton.sidhu@td.com'
	s=smtplib.SMTP(SERVER, 587, timeout=30)
	s.starttls()	
	s.login(user_name, password)	
	s.sendmail(user_name, target_email, msg)
	s.quit()

def IdentifyAttacks(model, df):

	results = model.Predict(df)
	results = map(model.labels.get, results)
	df['prediction'] = results
	uniqueAttacks = set(results)			
	uniqueAttacks.discard('clean')

	return df, uniqueAttacks
	

def PredictionProcess(logs, waitTime, logType):

	currTime = datetime.now() - timedelta(seconds = 10) + timedelta(hours = 4)
	startDate = currTime.strftime('%Y-%m-%dT%H:%M:%S')
	
	while True:
		
		
		uniqueAttacks = []
		endDate = datetime.now() - timedelta(seconds = 5) + timedelta(hours = 4)
		endDate = endDate.strftime('%Y-%m-%dT%H:%M:%S')
		failStr = logType + ": No Data for the time period " + startDate + " - " + endDate + ".\n"
				
		#For sanity print that the process is running
		print(logType + " is running for time range: " + startDate + " - " + endDate + ".")
		if logType is "DB":
			initdf = logs.DatabaseLogs.MySQLLogs(startDate, endDate)
			if initdf is not None:			
				df = logs.DatabaseLogs.Transform(initdf)
				model = Model('DB')
				predictedDF, uniqueAttacks = IdentifyAttacks(model, df)

			else:
				print(failStr)

		elif logType is "IIS":
			initdf = logs.WebLogs.IISLog(startDate, endDate)
			if initdf is not None:
				df = logs.WebLogs.Transform(initdf)
				model = Model('IIS')
				predictedDF, uniqueAttacks = IdentifyAttacks(model, df)
			else:
				print(failStr)
						
		if uniqueAttacks:
		        print(logType + " has detected the following attacks: " + " ".join(uniqueAttacks) + "\n")
		        notif = Mail("ALERT! " + logType + " has detected attacks.", logType + " has detected the following attacks: " + " ".join(uniqueAttacks) + "\n")
		        notif.send()
					
		startDate = endDate	
		t.sleep(waitTime)


def main():
	config = configparser.ConfigParser()
	config.read('config.ini')

	logs = Logs(config['network']['IP'])	
	waitTime = int(config['streaming']['delta'])
	
	Thread(target=PredictionProcess, args=(logs, waitTime, 'IIS',)).start()
	Thread(target=PredictionProcess, args=(logs, waitTime, 'DB',)).start()
	
	#_thread.start_new_thread(PredictionProcess, (waitTime, 'DB'))
	#_thread.start_new_thread(PredictionProcess, (waitTime, 'IIS'))	
	
				

if __name__ == '__main__':
	main()
