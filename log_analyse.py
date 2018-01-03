# -*- coding: utf-8 -*-
from datetime import datetime

access_log     = 'access_log.txt'
catalina       = 'catalina.out'
deny_file      = 'deny_list.txt'
deny_work_file = 'deny_work_list.txt'



###########################################################
# アクセス禁止画面が表示されたログをcatalina.outから取得する処理 #
###########################################################

def create_deny_list():
  deny_list = []
  with open(catalina, 'r') as f:
    write_file = open(deny_file, 'a')
    for row in f:
      if row.find('アクセスできませんの画面が表示されました。') >= 0:
        write_file.write(row)
  write_file.close()


###########################################################
# アクセス禁止リストから必要情報だけを取得する処理               #
###########################################################

def create_deny_work_list():
  deny_work_list = []
  with open(deny_file, 'r') as f:
    write_file = open(deny_work_file, 'a')
    for row in f:

      # For get [date].
      date_start = 0
      date_end   = row.find('thread:') - 1

      # For get [IP address].
      ip_start = row.find('IP : ') + 5
      ip_end   = row.find('; SESSIONID : ')

      deny_attr = "%s, %s\n" %(row[date_start : date_end], row[ip_start : ip_end])
      write_file.write(deny_attr)

  write_file.close()


###########################################################
# 解析ターゲットリスト作成処理                                #
###########################################################

def create_target_log_list(log_list, target_num):
  target_log_list = []
  counter = 0
  for i in log_list:
    if counter >= target_num:
      break
    else:
      target_log_list.append(i)
      counter += 1
  return target_log_list


###########################################################
# ログ解析処理                                              #
###########################################################

def log_analyse():
  # アクセス禁止リストを1行づつ読み込む
  with open(deny_work_file, 'r') as f:
    for row in f:
      row_length = len(row) - 1     # 改行コード削除のため-1を実施
      time = row[16:24]
      ip   = row[26:row_length]

      # アクセスログを展開し、取得したリストのIPのみ取得する
      filtered_a_log = []
      with open(access_log, 'r') as a_log:
        for a_log_row in a_log:
          if a_log_row.find(ip) >= 0:
            # print a_log_row
            filtered_a_log.append(a_log_row)

      # IPでフィルタしたリストに対し、時刻で検索してリストの何番目かを検索し
      # なんの処理でアクセス禁止が発生した処理を特定する
      target_num = 0
      for i in filtered_a_log:
        if i.find(time) >= 0:
          if i.find("GET /prod001/login HTTP/1.1") >= 0:
            target_num = filtered_a_log.index(i) - 1

      #  検索したエラー発生箇所の直前の処理を表示する。
      # print filtered_a_log[target_num]

      # requestのsessionIDが格納されているか判別する
      split_a_log = filtered_a_log[target_num].split(" ")
      # print split_a_log[7]    # Get resources
      # print split_a_log[11]   # request's sessionID
      # print split_a_log[12]   # referer
      # print split_a_log[13]   # response's sessionID


      # 条件分岐の本番ポイント
      # sessionIDが存在するかを確認する
      if split_a_log[11] == "-":
        print "requestのsessionIDなしのためアクセス禁止"
        # 前日タブ / 当日タブ判定
        # csrfToken取得
        if split_a_log[7].find("csrf=") >= 0:
          csrf_start = split_a_log[7].find("csrf=")
          csrf_end   = split_a_log[7][csrf_start:].find("&") + csrf_start
          # print csrf_start
          # print csrf_end
          # print split_a_log[7][csrf_start:csrf_end]

        # 検索対象より古いログのリストを作成する
          create_target_log_list(filtered_a_log, target_num)

          # 検索対象ログにcsrfTokenが存在しているか確認する
          # ****** TODO: ここの条件は見直しすること。********
          # for k in target_log_list:
          #   if split_a_log[7].find("csrf=") >= 0:
          #     print "GETにcsrfがあるので前日タブ"
          #   else:
          #     print "条件に引っかからないので当日"

      else:
        # print "requestのsessionIDあり. sessionID : " + split_a_log[11]
        # 前日タブ / 当日タブ判定
        # 検索対象より古いログのリストを作成する
        flg = 0
        for i in create_target_log_list(filtered_a_log, target_num):
          if i.find("JSESSIONID=" + split_a_log[11]) >= 0:
            flg = 1
            if i.find("GET /prod001/login") >= 0:
              flg = 2

        if flg == 1:
          print "当日発行のsessionIDありのため、当日タブ"
        elif flg == 2:
          print "当日発行のsessionIDありのため、当日タブ。ただしlogin画面を表示しただけのsessionIDを利用してrequestしている"
        else:
          print "当日発行のsessionIDなしのため、前日タブ"





###########################################################
# メイン処理                                                #
###########################################################
print datetime.now().strftime('%Y/%m/%d %H:%M:%S') + "| 処理開始"
create_deny_list()
create_deny_work_list()
log_analyse()
print datetime.now().strftime('%Y/%m/%d %H:%M:%S') + "| 処理完了"
