import configparser
import pickle

class Model():

    model = "Unassigned"
    labels = "Unassigned"

    def __init__(self, modelType):

        self.modelType = modelType
        config = configparser.ConfigParser()
        config.read('config.ini')
        modelFileName = config['models'][modelType]
        self.model = pickle.load(open(modelType + "Logs/" + modelFileName,"rb"))
        labelFileName = config['models']["labels"]
        self.labels = pickle.load(open(modelType + "Logs/" + labelFileName, "rb"))
        self.labels = dict((v,k) for k,v in self.labels.items())

    def Predict(self, df):

        results = self.model.predict(df)
        return results

        
        