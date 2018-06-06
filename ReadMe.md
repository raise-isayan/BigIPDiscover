Burp suite 拡張 BigIPDiscover
=============
このツールは、PortSwigger社の製品であるBurp Suiteの拡張になります。

## 概要

BipIPサーバが設定するCookieにはプライベートIPが含まれる場合があり、そのIPを検出するための
拡張になります。

脆弱性の詳細については以下を参照してください。

* https://www.owasp.org/index.php/SCG_D_BIGIP

Examples
````
BIGipServer<pool_name>=1677787402.36895.0000
BIGipServer<pool_name>=vi20010112000000000000000000000030.20480
BIGipServer<pool_name>=rd5o00000000000000000000ffffc0000201o80
BIGipServer<pool_name>=rd3o20010112000000000000000000000030o80
````

## 利用方法

Burp suite の Extenderは以下の手順で読み込めます。

1. [Extender]タブの[add]をクリック
2. [Select file ...]をクリックし、BigIPDiscover.jar を選択する。
3. ｢Next｣をクリックし、エラーがでてないことを確認後、「Close」にてダイヤログを閉じる。


## 必須ライブラリ
ビルドには別途 [BurpExtLib](https://github.com/raise-isayan/BurpExtLib) のライブラリを必要とします。
* BurpExtlib v1.7.30

以下のバージョンで動作確認しています。

* Burp suite v1.7.30

## 注意事項
このツールは、私個人が勝手に開発したもので、PortSwigger社は一切関係ありません。本ツールを使用したことによる不具合等についてPortSwiggerに問い合わせないようお願いします。

