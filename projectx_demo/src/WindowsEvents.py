from AllLogs import AllLogs

class WindowsEvents(AllLogs):

	def __init__(self, ip):
		AllLogs.__init__(self, ip)

	def SystemLog(self, start, end):
		#Usage of the scroll function for System Log
		index = 'winlogbeat-*'
		doc_type = 'doc'
		#query_body = {'query':{"match":{"log_name":"System"}}, 'sort':{"@timestamp":"desc"}}
		query_body = {"query": { 
					"bool": {
						"must": {
							"wildcard": {
								"log_name" : "*System"
								
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


		page_size = 10000
		raw_df = self.scroll(index, doc_type, query_body, debug=True)

		#Creating a Pandas DataFrame with individual parameters as columns

		#Creating a Soruce DataFrame
		list_source = []
		for i in range(len(raw_df)):
			source_values = raw_df['_source'].iloc[i]
			#pd.DataFrame(source_values)
			list_source.append(source_values)
		#source_values
		source_df = pd.DataFrame(list_source)

		#Creating a Event DataFrame
		list_event = []
		for i in range(len(raw_df)):
			try:
				event_values = raw_df['_source'].iloc[i]['event_data']
				list_event.append(event_values)
			except:
				#print(i)
				list_event.append(dict())

		event_df = pd.DataFrame(list_event)

		#Creating a Beat DataFrame
		list_beat = []
		for i in range(len(raw_df)):
			beat_values = raw_df['_source'].iloc[i]['beat']
			list_beat.append(beat_values)
		beat_df = pd.DataFrame(list_beat)

		#Merging all DataFrame into a single one
		raw_df = raw_df.reset_index()
		new_df = pd.concat([raw_df,source_df,event_df,beat_df], axis = 1)
		karthik = new_df

		return(karthik) 

	def SecurityLog(self, start, end):
		# Using Scroll Function for Security Log
		index = 'winlogbeat-*'
		doc_type = 'doc'
		#query_body = {'query':{"wildcard":{"log_name":"*Security"}}, 'sort':{"@timestamp":"desc"}}
		query_body = {"query": { 
					"bool": {
						"must": {
							"wildcard": {
								"log_name" : "*Security"
								
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


		page_size = 10000
		raw_df1 = self.scroll(index, doc_type, query_body, page_size=10000, debug=True, scroll='2m')
		raw_df1 = raw_df1.reset_index(drop=True)

		#Creating a Source DataFrame
		list_source = []
		for i in range(len(raw_df1)):
			source_values = raw_df1['_source'].iloc[i]
			list_source.append(source_values)
		source_df = pd.DataFrame(list_source)

		#Creating a Beat DataFrame
		list_beat = []
		for i in range(len(raw_df1)):
			beat_values = raw_df1['_source'].iloc[i]['beat']
			list_beat.append(beat_values)

		beat_df = pd.DataFrame(list_beat)
		beat_df = beat_df.drop(columns = ['version'])
		#all version are 6.2.4

		#Creating a Event DataFrame
		list_event_data = []
		for i in range(len(raw_df1)):
			try:
				event_data_values = raw_df1['_source'].iloc[i]['event_data']
				list_event_data.append(event_data_values)
			except:
				list_event_data.append(dict())

		for d in list_event_data:
			d.update((k, '') for k, v in d.items() if v == '-')

		event_data_df = pd.DataFrame(list_event_data)

		#Merging all DataFrame Together
		new_df = pd.concat([raw_df1,source_df, beat_df, event_data_df], axis = 1)
		new_df['@timestamp'] = pd.to_datetime(new_df['@timestamp'])
		new_df = new_df.fillna('')
		final_df = new_df.reset_index(drop = True)
		f = lambda i: str(int(i,16))
		final_df.ProcessId[final_df.ProcessId != ''] = final_df.ProcessId[final_df["ProcessId"] != ''].apply(f)
		final_df.SubjectLogonId[final_df.SubjectLogonId != ''] = final_df.SubjectLogonId[final_df["SubjectLogonId"] != ''].apply(f)
		#final_df.HandleId[final_df.HandleId != ''] = final_df.HandleId[final_df["HandleId"] != ''].apply(f)
		#more hex strings need to be decoded, need to detect first, a function would be best


		#paramNullCount = event_data_df.isnull().sum()/(event_data_df.shape[0])
		#sortedNullCount = sorted(paramNullCount.items(), key=lambda x: float(x[1]))

		#useful_dict = {k: v for k, v in paramNullCount.items() if v<0.9}

		#list_to_join = ['_id','@timestamp','event_id', 'Service', 'ProcessName','PrivilegeList','HandleId']
		#this list can be expanded(useful features)
		#L = list(useful_dict.keys())
		#for elem in list_to_join:
		#	if elem not in L:
		#		L.insert(0,elem)

		return(final_df)

	def ApplicationLog(self, start, end):

		doc = {"query": { 
                "match": {
                    "log_name" : "Application" 
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
						},					
       "sort": {
                "@timestamp": "desc"
               }
        }

		appdf = self.scroll("winlogbeat-*", "doc", doc, debug = True)

		_appsource = [item for item in appdf['_source']]

		for i in _appsource:
			if 'event_data' not in i.keys():
				i['event_data'] = {}

		_appeventdata = [item['event_data'] for item in pd.Series(appdf['_source']).values]
		#iisdf = pd.concat(map(pd.DataFrame.from_dict, iisRes['hits']['hits']), axis=1)['_source'].T
		appdf = pd.concat([pd.DataFrame(_appsource), pd.DataFrame(_appeventdata)], axis=1)
		appdf['@timestamp'] = pd.to_datetime(appdf['@timestamp'])
		appdf = pd.concat([appdf[["@timestamp","process_id"]], appdf.iloc[:,-27:]] , axis = 1)
		appdf = appdf.fillna('')

		return appdf
