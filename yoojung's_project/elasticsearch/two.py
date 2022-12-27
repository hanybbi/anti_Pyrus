from elasticsearch7 import Elasticsearch, helpers

def vaccine_anti(log) :
    _ES_URL = "27.96.130.210:9200"
    _ES_INDEX = "antipy_log"
    es_client = Elasticsearch(_ES_URL, timeout=60*1)

    es_client.index(index=_ES_INDEX, doc_type=__doc__, body=log)
