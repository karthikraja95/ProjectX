# -*- coding: utf-8 -*-
"""
For Demo
"""

from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC 
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import Select
import time
import random
import configparser
from pyvirtualdisplay import Display

class Mail:
	
	config = configparser.ConfigParser()
	config.read('config.ini')
	email_title = ''
	message = ''
	user_name = config['mail']['user']
	password = config['mail']['pw']
	target_email ='ashton.sidhu@td.com'

	def __init__(self, email_title, message):
		self.email_title = email_title
		self.message = message

	def add_driver(self):		
		driver = webdriver.Chrome("/home/secdevml/Downloads/chromedriver")
		return driver

	#set up webdriver to direct to the server
	def get_url(self, driver):
	    driver.get("https://accounts.google.com/signin/v2/identifier?continue=https%3A%2F%2Fmail.google.com%2Fmail%2F&service=mail&sacu=1&rip=1&flowName=GlifWebSignIn&flowEntry=ServiceLogin")

	def login(self, driver):
		driver.find_element_by_name("identifier").send_keys(self.user_name)
		driver.find_element_by_xpath("//*[@id = 'identifierNext']/content/span").click()
		driver.implicitly_wait(4)
		driver.find_element_by_name("password").send_keys(self.password)
		time.sleep(1)
		driver.find_element_by_xpath("//*[@id = 'passwordNext']/content/span").click()

	def subject_text(self, driver):
		composeElem = driver.find_element_by_class_name('z0')
		composeElem.click()

		toElem = driver.find_element_by_name("to")
		toElem.send_keys(self.target_email)

		subjElem = driver.find_element_by_name("subjectbox")
		subjElem.send_keys(self.email_title)

		editable = driver.find_element_by_css_selector('.editable')
		if editable:
			editable.click()
			editable.send_keys(self.message)

	def send_email(self, driver):
	    try:
    		send = driver.find_elements_by_xpath('//div[@role="button"]')
    		for s in send:
    			if s.text.strip() == 'Send':
    				s.click()
    				break
	    except:
	    	print("Email sending failed")

	def quit(self, driver):
	    driver.quit()

	def send(self):	

		display = Display(visible=0, size=(800,600))
		display.start()		
		driver = self.add_driver()
		self.get_url(driver)
		self.login(driver)
		self.subject_text(driver)
		#time.sleep(2)
		self.send_email(driver)
		time.sleep(3)
		self.quit(driver)
		display.stop()
			
	
	
	
	
	
