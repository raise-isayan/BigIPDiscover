Burp suite 拡張 BigIPDiscover
=============

Language/[English](Readme.md)

このツールは、PortSwigger社の製品であるBurp Suiteの拡張になります。


Burp ProfessionalのScannerに対応しています。
また、Burp Communityの場合でもProxyのHistory機能を利用して検出できます。

## 概要
F5ネットワークスのBIG-IPが設定するCookieにはプライベートIPが含まれる場合があり、
これはそのIPを検出するための拡張になります。

脆弱性の詳細については以下を参照してください。

* https://www.owasp.org/index.php/SCG_D_BIGIP
* https://support.f5.com/csp/article/K6917

Examples.
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

## 設定 
拡張を読み込むと[BIG-IP Cookie]タブが表示されます。
ここには「Decrypt」、「Options」のタブがありここから設定等を行うことが可能です。

### Decrypt タブ
EncryptされたBigIPの値をDecryptします。
上側の入力欄にDecryptを指定後、[Decrypt]ボタンをクリックすることで、Decryptされた値が
下側の入力欄に表示されます。

![Decrypt Tab](/image/Decrypt.png)

### Options タブ
BigIPのスキャンオプションの設定を行います。

![Options Tab](/image/Options.png)

#### Scan Header
スキャン対象を指定します。
 + Response Set-Cookie
     + 設定をはずすことはできません
 + Request Cookie
     + Request Cookie もスキャン対象とします。

#### Detection Option
検出する対象の設定
 + Privat IP Only
     + Private IP のみを検出します。

#### Free version scan option
Community Edition(Free)バージョンのみで有効な設定です。
  + item highlight
      + 検出した場合にHistoryにつける色を指定します。
  + comment
      + 検出した場合にコメントを書き換えます。

## コマンドラインオプション
コマンドラインからCookieの値をデコードすることが可能です。

```
java -jar BigIpDiscover.jar -d <encrypt>
```

<encrypt> にデコードしたいCookieを指定します。
例を示します。

例)
```
java -jar BigIpDiscover.jar -d BIGipServer16122=1677787402.36895.0000
IP addres: 10.1.1.100:8080
PrivateIP: true
```

## ビルド

```
gradlew release
```

## 必須ライブラリ
ビルドには別途 [BurpExtensionCommons](https://github.com/raise-isayan/BurpExtensionCommons) のライブラリを必要とします。
* BurpExtensionCommons v0.4.x

### 利用ライブラリ

* google gson (https://github.com/google/gson)
  * Apache License 2.0
  * https://github.com/google/gson/blob/master/LICENSE

以下のバージョンで動作確認しています。
* Burp suite v2.1.07

## 注意事項
このツールは、私個人が勝手に開発したもので、PortSwigger社は一切関係ありません。本ツールを使用したことによる不具合等についてPortSwiggerに問い合わせないようお願いします。
