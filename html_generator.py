import datetime
import matplotlib as mpl
import matplotlib.pyplot as plt
import collections
from collections import OrderedDict

import access_log_analyzer as ala

class HtmlGenerator() :
  hour_graph_path    = '/var/www/html/honeypot/hour.png'
  country_graph_path = '/var/www/html/honeypot/country.png'
  result_html_path   = '/var/www/html/honeypot/index.html'
  target_date = datetime.date.today()
  analyzer = ala.AccessLogAnalyzer(target_date)


  def generate(self) :
    # アクセスログをCSV形式に変換
    self.analyzer.log2csv()

    # グラフを作る
    self.make_graph_by_hour()
    self.make_graph_by_country()

    # HTMLファイルを作る
    contents  = '<html>\n<head>\n<title>Honeypot</title>\n<style>\n'
    contents += 'table {border: solid 1px #000000; border-collapse: collapse;}\n'
    contents += 'th, td {border: solid 1px #000000;}\n'
    contents += '</style>\n</head>\n<body>\n<center>\n'
    contents += '<h1>Result</h1>\n'
    contents += '<h2>Summary</h2>\n'
    contents += '<table>\n'
    contents += '<tr><td>Update time</td><td>' + datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S') + '</td></tr>'
    contents += '<tr><td>Target date</td><td>' + self.target_date.strftime('%Y/%m/%d') + '</td></tr>'
    contents += '<tr><td>Number of accesses</td><td>' + str(self.analyzer.all_access_num) + '</td></tr>'
    contents += '</table>'
    contents += '<h2>Hour</h2>\n'
    contents += '<img src="hour.png" width="1024">\n'
    contents += '<h2>Access path</h2>\n'
    contents += self.make_table_by_access_path()
    contents += '<h2>Country</h2>\n'
    contents += '<img src="country.png">\n'
    contents += self.make_table_by_country()
    contents += '</center></body></html>'
    with open(self.result_html_path, 'w') as f:
      f.write(contents) 


  def make_table_by_access_path(self) :
    # アクセス数を数え、ソートする
    ordered_counts = collections.OrderedDict(self.analyzer.count(4))
    sorted_counts = collections.OrderedDict(
      sorted(ordered_counts.items(), key=lambda x: x[1], reverse=True)
    )

    # テーブルを作る
    table = '<table>\n<tr>\n<th>Access path</th><th>Number of accesses</th>\n</tr>\n'
    cnt = 0
    for k, v in sorted_counts.items() :
      if cnt < 10:
        table += '<tr>\n<td>' + k + '</td><td>' + str(v) + '</td>\n</tr>\n'
      cnt += 1
    return table + "</table>\n"


  def make_table_by_country(self) :
    # アクセス数を数え、ソートする
    ordered_counts = collections.OrderedDict(self.analyzer.count(3))
    sorted_counts = collections.OrderedDict(
      sorted(ordered_counts.items(), key=lambda x: x[1], reverse=True)
    )

    # テーブルを作る
    cnt = 0
    table = '<table>\n<tr>\n<th>Country</th><th>Number of accesses</th>\n</tr>\n'
    for k, v in sorted_counts.items() :
      if cnt < 10:
        table += '<tr>\n<td>' + k + '</td><td>' + str(v) + '</td>\n</tr>\n'
      cnt += 1
    return table + "</table>\n"


# 時間ごとのアクセス数のグラフを描く
  def make_graph_by_hour(self) :
    # アクセス数を数える
    hours = [ '0:00',  '1:00',  '2:00',  '3:00',  '4:00',  '5:00', \
              '6:00',  '7:00',  '8:00',  '9:00', '10:00', '11:00', \
             '12:00', '13:00', '14:00', '15:00', '16:00', '17:00', \
             '18:00', '19:00', '20:00', '21:00', '22:00', '23:00']
    counts = self.analyzer.count_by_hour()

    # グラフを作る
    fig = plt.figure(figsize=(22, 4))
    ax = fig.add_subplot(111)
    ax.set_xlabel('Hours')
    ax.set_ylabel('Accesses')
    plt.fill_between(hours, counts)
    plt.plot(hours, counts)
    plt.xlim(0, 23)
    plt.ylim(0,)
    fig.savefig(self.hour_graph_path)


# 宛先元国ごとのアクセス数のグラフを描く
  def make_graph_by_country(self) :
    # アクセス数を数え、ソートする
    ordered_counts = collections.OrderedDict(self.analyzer.count(3))
    sorted_counts = collections.OrderedDict(
      sorted(ordered_counts.items(), key=lambda x: x[1], reverse=True)
    )
    
    # 6位以降を「その他」扱いする
    counts_keys = list(sorted_counts.keys())[0:5]
    counts_keys.append('Others')
    counts_values = list(sorted_counts.values())[0:5]
    counts_other_values = list(sorted_counts.values())[5:]
    counts_values.append(sum(counts_other_values))
    
    # グラフを作る
    fig = plt.figure()
    plt.pie(counts_values, labels=counts_keys,
            counterclock=False, startangle=90, autopct='%1.1f%%')
    fig.savefig(self.country_graph_path)

