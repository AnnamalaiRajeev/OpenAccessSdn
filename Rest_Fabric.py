import requests
from Ofctl_statistics_mappings import *
from ryu import *
import json
import redis


def add_flow(priority=65521, dpid=None, ipv4_src=None, table_id=None):

    with open('flow_add.json', 'r') as f:
        data = json.load(f)
        if ipv4_src:
            data['match']['ipv4_src'] = ipv4_src
        if priority:
            data['priority'] = priority
        if dpid:
            data['dpid'] = dpid
        if table_id:
            data['table_id'] = table_id

    print(data)
    _add_flow = requests.post(url='http://192.168.56.104:8080/flowentry/add',data=json.dumps(data))
    if _add_flow.ok:
        return _add_flow
    else:
        return False


def create_redis_clinet(server_ip,port=None):
    if port == None:
        client = redis.Redis(server_ip, port=6379)
    else:
        client = redis.Redis(server_ip,port=port)
    return client


def wrap_requests(func):
    def wrapper(*args, **kwargs):
        return_value = func(*args, **kwargs)
        if return_value.ok:
            print(return_value.json())
            print(return_value.status_code)
        if return_value:
            return return_value
        else:
            return None
    return wrapper


@wrap_requests
def request_get(Content_To_Retrieve):
    response = requests.get('http://192.168.56.104:8080/{}'.format(Content_To_Retrieve))
    return response


if __name__ == '__main__':

    response_Dpids = request_get(Switch_DPIDs)
    response_switch_stats = request_get(Switch_Description)
    response = request_get(Switch_Flow)
    response = request_get(Switch_Table_Features)
    response = request_get(Switch_Port_Stats)
    client = create_redis_clinet('192.168.56.104')

    _customers = client.hgetall(name='authentication_status')
    for _customer in _customers:
        _customer = _customer.decode()
        print(_customer)
        results = map(add_flow, [65500], [1], [_customer], [1]) #lazy iterator
        for result in results:
            pass
#





