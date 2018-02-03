# -*- coding: utf-8 -*-
from datetime import datetime
import os

compare_date   = '2018/01/31'         # yyyy/mm/dd形式で記述すること。当日タブ判定日付
target_env     = 'prod002'            # 環境指定

access_log     = 'access_log.txt'
catalina       = 'catalina.out'
deny_file      = 'deny_list.txt'
deny_work_file = 'deny_work_list.txt'
result         = ''
result_list    = []
result_file    = 'result.txt'

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

def log_analyse(result):
  # アクセス禁止リストを1行づつ読み込む
  with open(deny_work_file, 'r') as f:
    for row in f:
      print row
      row_length = len(row) - 1     # 改行コード削除のため-1を実施
      time = row[16:24]
      ip   = row[26:row_length]
      result = ""                # resultの初期化
      result = row[:row_length]

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
          # if i.find("GET /prod001/login HTTP/1.1") >= 0:
          if i.find("GET /%s/login HTTP/1.1" % target_env) >= 0:
            target_num = filtered_a_log.index(i) - 1

      #  検索したエラー発生箇所の直前の処理を表示する。
      # print filtered_a_log[target_num]
      # エラー発生を引き起こした操作を取得
      split_a_log = filtered_a_log[target_num].split(" ")
      # print u"Get resources : " + split_a_log[7]       # Get resources

      # 環境確認
      # if split_a_log[7].find("prod001") >= 0:
      if split_a_log[7].find(target_env) >= 0:
      	print u"%sです" % target_env
      	# print u"prod001です"
      else:
      	print u"そのほかの環境です"
      	continue


      # For get [logintime].
      if split_a_log[7].find("logintime=") >= 0:
  	    logintime_start = split_a_log[7].find("logintime=") + 10
	    logintime_end   = logintime_start + 10
	    logindate = split_a_log[7][logintime_start:logintime_end]
      else:
      	logindate = 0

      # For get [loginid].
      if split_a_log[7].find("loginid=") >= 0:
  	    loginid_start = split_a_log[7].find("loginid=") + 8
	    loginid_end   = loginid_start + 9
	    loginid = split_a_log[7][loginid_start:loginid_end]
      else:
      	loginid = "ログインID取得できません"

      result += ", " + str(logindate)
      result += ", " + loginid

      # print u"loginID : " + loginid
      # print u"request's sessionID : " + split_a_log[11]   # request's sessionID
      # print u"referer : " + split_a_log[12]            # referer
      # print u"response's sessionID : " + split_a_log[13]   # response's sessionID

      ############# 条件分岐の本番ポイント ####################

      #### step1 当日/前日タブの判定を行なう
      if logindate == compare_date:
      	result += ", 当日タブ,"
      elif logindate == 0:
      	result += ", logindateのパラメタなしのため判定不可,"
      elif logindate != compare_date:
      	result += ", 前日タブ,"
      else:
      	result += ", *****例外*****,"

      #### step2 sessionIDが存在するかを確認する
      if split_a_log[11] == "-":
      	result += " requestのsessionIDなしのためアクセス禁止"
      else:
        # 検索対象より古いログのリストを作成する
        flg = 0
        for i in create_target_log_list(filtered_a_log, target_num):
          if i.find("JSESSIONID=" + split_a_log[11]) >= 0:
            flg = 1
            # if i.find("GET /dev001/login") >= 0:
            #   flg = 2

        if flg == 1:
          result += " 当日発行のsessionIDありでアクセス禁止発生"
        # elif flg == 2:
        #   # print u"当日発行のsessionIDありのため、当日タブ。ただしlogin画面を表示しただけのsessionIDを利用してrequestしている"
        #   result += u" 当日発行のsessionIDありのため、当日タブ。ただしlogin画面を表示しただけのsessionIDを利用してrequestしている"
        else:
          result += " 当日発行のsessionIDなしでアクセス禁止発生"

      result_list.append(result)


###########################################################
# メイン処理                                                #
###########################################################
print datetime.now().strftime('%Y/%m/%d %H:%M:%S') + u"| 処理開始"

if os.path.exists(deny_file) :
	print u"ファイル初期化します" + deny_file
	os.remove(deny_file)
if os.path.exists(deny_work_file):
	print u"ファイル初期化します" + deny_work_file
	os.remove(deny_work_file)

print datetime.now().strftime('%Y/%m/%d %H:%M:%S') + u"| 禁止リスト作成開始"
create_deny_list()
print datetime.now().strftime('%Y/%m/%d %H:%M:%S') + u"| 禁止リスト作成終了"

print datetime.now().strftime('%Y/%m/%d %H:%M:%S') + u"| 禁止リストワーク作成開始"
create_deny_work_list()
print datetime.now().strftime('%Y/%m/%d %H:%M:%S') + u"| 禁止リストワーク作成終了"

print datetime.now().strftime('%Y/%m/%d %H:%M:%S') + u"| ログ解析処理開始"
log_analyse(result)
print datetime.now().strftime('%Y/%m/%d %H:%M:%S') + u"| ログ解析処理終了"

# resultをファイルに書き込む
print u"結果出力開始"
f = open(result_file, 'w') 
for i in result_list:
  f.write(i + "\n")
f.close()

print u"結果出力終了"
print datetime.now().strftime('%Y/%m/%d %H:%M:%S') + u"| 処理完了"
