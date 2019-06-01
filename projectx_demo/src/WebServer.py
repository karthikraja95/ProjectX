from AllLogs import AllLogs
import pandas as pd
from  collections import Counter
import re
import pickle

class WebServer(AllLogs):

	def __init__(self, ip):
		AllLogs.__init__(self, ip)

	def IISLog(self, start, end):

		doc = {"query": { 
					"bool": {
						"must": {
							"wildcard": {
								"log_name" : "*IIS-Logging*"
								
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



		iisdf = self.scroll("winlogbeat-*", "doc", doc, page_size=10000, debug = False)
		if "_source" not in iisdf.columns:
			return None
		_source = [item for item in iisdf['_source']]
		_eventdata = [item['event_data'] for item in pd.Series(iisdf['_source']).values]

		#iisdf = pd.concat(map(pd.DataFrame.from_dict, iisRes['hits']['hits']), axis=1)['_source'].T
		iisdf = pd.concat([pd.DataFrame(_source), pd.DataFrame(_eventdata)], axis=1)

		#iisdf['referer'] = [item.split('referer')[1].strip() if "referer" in str(item) else "" for item in pd.Series(iisdf['CustomFields']).values]


		iisdf['@timestamp'] = pd.to_datetime(iisdf['@timestamp'])
		iisdf['servertime'] = pd.to_datetime(iisdf['date'].astype(str) + ' ' + iisdf['time'].astype(str))
		iisdf = iisdf.sort_values("servertime")

		ips = {}
		timeBetweenRequests = []

		for ind,item in enumerate(iisdf['c-ip']):
			if item not in ips:
				ips[item] = iisdf.servertime.iloc[ind]
				timeBetweenRequests.append(-999.0)
			else:
				delta = (iisdf.servertime.iloc[ind] - ips[item]).seconds
				timeBetweenRequests.append(delta)
				ips[item] = iisdf.servertime.iloc[ind]

		iisdf['TimeBetweenRequests'] = timeBetweenRequests

		iisdf = iisdf[['@timestamp', 'servertime', 'TimeBetweenRequests', 'c-ip', 'cs-bytes', 'sc-bytes', 's-ip', 'cs-method', 'cs-uri-query','cs-uri-stem', 'csCookie', 'csReferer', 'csUser-Agent', 's-port', 'sc-status']]
		return iisdf

	@classmethod
	def Transform(self, iisdf):
		status = ['200', '206', '302', '304', '404', '500']
		value = iisdf['cs-method']

		def cs_method_binary(value):
			#value = iisdf['cs-method']
			if ((value == 'GET') | (value == 'POST') | (value == 'PUT') | (value == 'PATCH') | (value == 'DELETE')):
				binary = 0
			else:
				binary = 1
			return binary

		iisdf['cs_method_blue_or_red'] =  iisdf['cs-method'].apply(cs_method_binary)

		iisdf['user_agent'] = [x.strip().replace('+', ' ') for x in iisdf['csUser-Agent']]		

		ua = open('IISLogs/useragent.txt', 'r')
		uadata = ua.read()
		uastring = [i for i in uadata.splitlines() if i.strip()!= '']	

		def user_agent_binary(ua_series):			
			if ua_series in uastring:
				#if i == j:
				binary = 0
			else:
				binary = 1

			return binary		


		with open ('IISLogs/wordlist', 'rb') as fp:
			wordlist = pickle.load(fp)
		iisdf['user_agent_blue_or_red'] =  iisdf['user_agent'].apply(user_agent_binary)

		iisdf = iisdf[['TimeBetweenRequests', 'cs-bytes', 'sc-bytes',
            'cs-method', 'cs-uri-query', 's-port', 'sc-status',
            'user_agent_blue_or_red']]

		query = iisdf['cs-uri-query']
		query_list = query.tolist()
		countlist = []
		statusLog = []
		#wordlist = vectorizer_query.get_feature_names()
		for row in iisdf.itertuples():
			tempCounter = Counter([word for word in re.findall(r'\w+', row[4])])
			# if the word appears in the doc, then 1, else 
			topkinDoc = [1 if tempCounter[word] > 0 else 0 for word in wordlist]
			statusinLog = [1 if item in row[4] else 0 for item in status]
			# create a list for top k words with encoded target and its label
			countlist.append(topkinDoc)
			statusLog.append(statusinLog)

		count_vec_query_df = pd.DataFrame(countlist,columns = wordlist)
		statusDF = pd.DataFrame(statusLog, columns=status)

		iisdf = pd.concat([statusDF, count_vec_query_df, iisdf],axis = 1)
		iisdf = iisdf.drop('cs-uri-query', axis=1)

		cat_df = iisdf[['s-port']]

		iisdf = iisdf.drop(['cs-method','s-port','sc-status'], axis = 1)

		cat_df = pd.get_dummies(cat_df, columns=cat_df.columns)

		iisdf = pd.concat([cat_df, iisdf], axis = 1)

		iisdf = pd.DataFrame(iisdf).fillna(0)

		return iisdf
 

