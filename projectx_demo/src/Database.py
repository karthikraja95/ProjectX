from AllLogs import AllLogs
import pandas as pd
import string
import re
from collections import Counter
import numpy as np


class DatabaseLogs(AllLogs):

	def __init__(self, ip):
		AllLogs.__init__(self, ip)

	def MySQLLogs(self, start, end):	

		doc = {"query": { 
					"bool": {
						"must": {
							"wildcard": {
								"source" : "*\\general.log"
								
								}
						},
						"filter": {
							"bool": {
								"must": {
									"range":{
										"@timestamp": {
											"gte": start,
											"lt": end
											}
										}
								}
							}
						}
					}                      
				},
			"sort": {
						"@timestamp": "asc"
					}
			}

		dbdf = self.scroll("filebeat-*", "doc", doc, page_size=10000, debug = False)

		if "_source" not in dbdf.columns:
			return None

		_dbsource = [item for item in dbdf['_source']]
		dbdf = pd.DataFrame(_dbsource)

		serverTime = []
		queryType = []
		query = []

		for x in dbdf['message']:
			
			if len(x.split('\t')) == 3:        
				serverTime.append(x.split('\t')[0])
				queryType.append(x.split('\t')[1])
				query.append(x.split('\t')[2])
			
			else:
				serverTime.append("")
				queryType.append("")
				query.append(' '.join(x.split('\t')))
					
		dbdf['servertime'] = serverTime
		dbdf['type'] = queryType
		dbdf['query'] = query
		dbdf['servertime'] = pd.to_datetime(dbdf['servertime'])
		dbdf['@timestamp'] = pd.to_datetime(dbdf['@timestamp'])
		dbdf[['servertime', 'type', 'source', 'query']]
		dbdf['type'] = [item[item.find(' '):] if item != '' else "" for item in dbdf['type']]
		dbdf['command'] = [item[:item.find(' ')] for item in dbdf["query"]]
		dbdf['where'] = [item[item.find('WHERE') + len('WHERE '):] if 'WHERE' in item else '' for item in dbdf["query"]]

		return dbdf

	@classmethod
	def Transform(self, df):

		#return cleaned query length
		def query_clean(s):
			translator = str.maketrans('', '', string.punctuation)
			return s.translate(translator)

		def query_length(s):
			return len(s)

		def sleep_check(s):
			list_of_sleep = ['SLEEP', 'WAITFOR', 'DELAY', 'pg_sleep','sleep']
			'''
			This is list to be expanded if more types of databases are considered.
			OracleDB: SLEEP
			MS SQL Server: WAITFOR DELAY
			IBM DB2: n/a, require additional function/loop ref:http://www.sqlpl-guide.com/example-db2-sleep-command/
			SAP Sybase ASE: WIATFOR DELAY
			Postgre SQL: pg_sleep
			MariaDB: SLEEP
			MySQL: SLEEP
			Teradata: SLEEP
			IBM Infomix: sleep, eg. SYSTEM "sleep10"
			Ingres: sleep
			Amazon's simpleDB: sleep eg. Thread.sleep(sometime)
			'''
			for word in list_of_sleep:
				if word in s:
					return 1
				else:
					return 0

		'''
		Complexity measurement of sql query
		reference: http://www.sqlusa.com/bestpractices/sql-query-complexity/
		method: Complexity = number of tables + number of SELECT/INSERT/UPDATE/MERGE columns + number of JOINs +
		number of WHERE clause predicates + number of GROUP BY columns + number of WHEN clauses in CASE expressions +
		number of sytem function references + number of UDF references + number of function nestings + number of UNIONs
		'''
		score_list = ['FROM','SELECT', 'INSERT','UPDATE','MERGE','JOIN', 'WHERE','GROUP BY', 'ORDER BY','WHEN','UNION']
		def complexity(s):
			score = 0
			for elem in score_list:
				score += s.count(elem)
			return score  

		def comment_check(s):
			for elem in ['--', '*/','/*']:
				if elem in s:
					return 1
				else:
					return 0
			
			
		'''
		By now only hex string is checked. Further work should be done on checking if every single token in the query has
		semantics. 
		No existing dictionary to be found efficient and accurate.
		Possibly a ML model to classify.
		'''
		def hex_check(s):
			indicator = 0
			for item in re.findall(r"[\w]+", s):
				if re.match(r"(0[xX])?[A-Fa-f0-9]+$", item):
					if bool(re.match('^(?=.*[0-9])(?=.*[a-zA-Z])',item)):
						indicator = 1
						pass
			return indicator

		'''
		In case of multiple repeating adjacent words, only the one with highest frequency is selected
		'''
		def number_adjacent_repeats(s):
			if s == '':
				value = 0
				pass
			temp = re.findall(r"[\w]+",s)
			z = list(zip(temp, temp[1:]))
			mylist = []
			for elem in z:
				if elem[0] == elem[1]:
					mylist.append(elem[0])
			if len(mylist) != 0:
				value = Counter(mylist).most_common(1)[0][1] +1
			else:
				value = 0
			return value
		
		dummyList = []

		commands = list(df['command'])

		list_of_commands = ['select','update','create','selete','insert','alter','drop']

		for item in commands:
			list_of_dummies = list(1 if cmd in item.lower() else 0 for cmd in list_of_commands )
			dummyList.append(list_of_dummies)

		dummy = pd.DataFrame(dummyList,columns = list_of_commands)
		df = pd.concat([df, dummy], axis = 1)
		df = df.fillna('')
		df['query_cleaned'] = df['query'].apply(query_clean)
		df['cleaned_query_length'] = df['query_cleaned'].apply(query_length)
		df['sleep_check'] = df['query'].apply(sleep_check)
		df['complexity'] = df['query'].apply(complexity)
		df['comment_check'] = df['query'].apply(comment_check)
		df['hex_check'] = df['query'].apply(hex_check)
		df['repeats'] = df['query'].apply(number_adjacent_repeats)
		L = ['select','create','insert','alter','drop','cleaned_query_length','sleep_check','complexity','comment_check','hex_check','repeats']
		final_columns = list(item for item in L if item in list(df.columns))

	
		return df[final_columns]

		
		
