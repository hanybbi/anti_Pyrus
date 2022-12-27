import json
from elasticsearch7 import Elasticsearch, helpers

_ES_URL = "27.96.130.210:9200"
_ES_INDEX = "antipy_log"
#_DOC_TYPE = _ES_INDEX
es_client = Elasticsearch(_ES_URL, timeout=60*1)

query_DSL = {
    "query" : {
        "match" : {
            "virus detection" : " malware_sample3"
        }
    }
}


print(es_client.search(index=_ES_INDEX, body=query_DSL))
