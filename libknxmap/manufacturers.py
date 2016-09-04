import json


def get_manufacturer_by_id(mid):
    assert isinstance(mid, int)
    m = json.load(open('libknxmap/data/manufacturers.json'))
    for _m in m.get('manufacturers'):
        if int(_m.get('knx_manufacturer_id')) == mid:
            return _m.get('name')
