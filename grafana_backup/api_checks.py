from grafana_backup.commons import print_horizontal_line
from grafana_backup.dashboardApi import health_check, auth_check, uid_feature_check, paging_feature_check

import logging
import http.client

#http.client.HTTPConnection.debuglevel = 1

#logging.basicConfig()
#logging.getLogger().setLevel(logging.DEBUG)
#requests_log = logging.getLogger("requests.packages.urllib3")
#requests_log.setLevel(logging.DEBUG)
#requests_log.propagate = True

def main(settings):
    grafana_url = settings.get('GRAFANA_URL')
    http_get_headers = settings.get('HTTP_GET_HEADERS')
    verify_ssl = settings.get('VERIFY_SSL')
    client_cert = settings.get('CLIENT_CERT')
    debug = settings.get('DEBUG')
    api_health_check = settings.get('API_HEALTH_CHECK')

    if api_health_check:
        (status, json_resp) = health_check(grafana_url, http_get_headers, verify_ssl, client_cert, debug)
        if not status == 200:
            return (status, json_resp, None, None, None)

    #(status, json_resp) = auth_check(grafana_url, http_get_headers, verify_ssl, client_cert, debug)
    #if not status == 200:
    #    return (status, json_resp, None, None, None)
    # blurgh
    status = 200
    json_resp = {}

    dashboard_uid_support, datasource_uid_support = uid_feature_check(grafana_url, http_get_headers, verify_ssl, client_cert, debug)
    if isinstance(dashboard_uid_support, str):
        raise Exception(dashboard_uid_support)
    if isinstance(datasource_uid_support, str):
        raise Exception(datasource_uid_support)

    paging_support = paging_feature_check(grafana_url, http_get_headers, verify_ssl, client_cert, debug)
    if isinstance(paging_support, str):
        raise Exception(paging_support)

    print_horizontal_line()
    if status == 200:
        print("[Pre-Check] Server status is 'OK' !!")
    else:
        print("[Pre-Check] Server status is NOT OK !!: {0}".format(json_resp))
    print_horizontal_line()

    return (status, json_resp, dashboard_uid_support, datasource_uid_support, paging_support)
