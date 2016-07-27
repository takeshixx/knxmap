import json

def get_manufacturer_by_id(id):
    assert isinstance(id, int)
    m = json.load(open('libknxmap/manufacturers.json'))
    for _m in m.get('manufacturers'):
        if int(_m.get('knx_manufacturer_id')) == id:
            return _m.get('name')