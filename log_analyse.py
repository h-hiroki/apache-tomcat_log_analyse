# -*- coding: utf-8 -*-

access_log = 'access_log.txt'
catalina   = 'catalina.out'
deny_file  = 'deny_list.txt'

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


#############
# メイン処理 #
#############

create_deny_list()
print '処理完了'

