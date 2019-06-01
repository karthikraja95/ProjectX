import requests
from elasticsearch import Elasticsearch
import pandas as pd
import numpy as np
import math
from  collections import Counter
import re

class AllLogs():

	def __init__(self, ip):
		self.es = Elasticsearch([ip])
	
	def scroll(self, index, doc_type, query_body, page_size=100, debug=True, scroll='2m'):
		es = self.es
		#debug = True
		dflist = []
		page = es.search(index=index, doc_type=doc_type, scroll=scroll, size=page_size, body=query_body)
		sid = page['_scroll_id']
		scroll_size = page['hits']['total']
		total_pages = math.ceil(scroll_size/page_size)
		page_counter = 0
		if debug: 
			print('Total items : {}'.format(scroll_size))
			print('Total pages : {}'.format( math.ceil(scroll_size/page_size) ) )
		# Start scrolling
		dflist.append(pd.DataFrame(page['hits']['hits']))
		while (scroll_size > 0):
			# Get the number of results that we returned in the last scroll
			scroll_size = len(page['hits']['hits'])  
			if scroll_size>0:
				if debug: 
					print('> Scrolling page {} : {} items'.format(page_counter, scroll_size))
				
			# get next page
			page = es.scroll(scroll_id = sid, scroll = '2m')
			# get all data into dataframes to be concatenated
			dflist.append(pd.DataFrame(page['hits']['hits']))
			page_counter += 1
			# Update the scroll ID
			sid = page['_scroll_id']
			
		df = pd.concat(dflist, axis = 0)
		return df

	def Transform(df):
		return df