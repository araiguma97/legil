import csv
import sys
import datetime
import geoip2.database

class AccessLogAnalyzer:
  # パス
  log_path           = '/home/araiguma97/legil/access_log'
  geoip_db_path      = '/home/araiguma97/legil/GeoLite2-Country_20201229/GeoLite2-Country.mmdb'
  csv_path           = '/home/araiguma97/legil/access_log.csv'

  # 変数
  all_access_num = 0


  def __init__(self, target_date):
    self.target_date = target_date


  # ログをCSV形式に変換する
  def log2csv(self) :
    with open(self.log_path, 'r') as f_in, \
         open(self.csv_path, 'w') as f_out:
      reader = csv.reader(f_in, delimiter=' ')
      l_in = [row for row in reader]
      writer = csv.writer(f_out)

      for row_in in l_in :
        # 日付と時間を解析する
        formatted_date = datetime.datetime.strptime(row_in[0], '[%Y-%m-%d')
        if formatted_date.strftime('%Y-%m-%d') != self.target_date.strftime('%Y-%m-%d') :
          continue
        formatted_time = datetime.datetime.strptime(row_in[1], '%H:%M:%S+0900]')
        country        = self.lookup_country(row_in[2], self.geoip_db_path)

        # CSV形式で出力する
        row_out = []
        row_out.append(formatted_date.strftime('%Y-%m-%d'))  # 0) 日付
        row_out.append(formatted_time.strftime('%H:%M:%S'))  # 1) 時間
        row_out.append(row_in[2])                            # 2) 送信元IPアドレス
        row_out.append(country)                              # 3) 送信元国名
        row_out.append(row_in[4])                            # 4) アクセスパス
        writer.writerow(row_out)
        self.all_access_num += 1


  # IPアドレスから国名を検索する
  def lookup_country(self, ip_address, geoip_db_path) :
    reader = geoip2.database.Reader(geoip_db_path)
    response = reader.country(ip_address)
    return response.country.names['en']
 

  # アクセス数を時間ごとに数える
  def count_by_hour(self) :
    with open(self.csv_path, 'r') as f :
      reader = csv.reader(f)
      l = [row for row in reader]

    counts = [0] * 24
    for row in l :
      hour = int(row[1][0:2])
      counts[hour] = counts[hour] + 1
    return counts


  # アクセス数を要素ごとに数える
  def count(self, index) :
    with open(self.csv_path, 'r') as f :
      reader = csv.reader(f)
      l = [row for row in reader]

    counts = {}
    for row in l :
      target = row[index]
      if target in counts :
        counts[target] = counts[target] + 1
      else :
        counts[target] = 1
    return counts

