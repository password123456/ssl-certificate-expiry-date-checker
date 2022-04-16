# ssl_certificate_expiry_date_checker
![made-with-python][made-with-python]
![Python Versions][pyversion-button]
[![Hits](https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2Fpassword123456%2Fhit-counter&count_bg=%2379C83D&title_bg=%23555555&icon=&icon_color=%23E7E7E7&title=hits&edge_flat=false)](https://hits.seeyoufarm.com)


[pyversion-button]: https://img.shields.io/pypi/pyversions/Markdown.svg
[made-with-python]: https://img.shields.io/badge/Made%20with-Python-1f425f.svg

- Scan a list of domains to find out which SSL Certificates each one is using.
- The goal is to find out which are about to expire. so I know to include that domain on our list of devices that we'll need to renew the certificate on when it expires.
- You can get a variety of information from the scan results. expire date, issuer, signature, certificate serial_number.
- If you're the ssl cerificate Officer in your organization, You can do get a list of domain from in your organization to check the expiration date of the ssl certificates.
- Send a custom notification when SSL certificates are about to expire with a detailed scan results using webhook (telegram-bot, slack..etc)
- you can management not to be the ssl certificate expire.
- The difference from other similar tools,You can optionally choose to use proxy each list. for example, there's a certain system in the restricted private network, you have to scan it. in this case you may have to use  proxy system.
- you can set the proxy ip/port in the configuraion, can set which domains must pass through the proxy system in the list.txt.
- If you have a various log analyzer, you can collect logs and do what you want to more.

# Documentation
```python
# pip install pyOpenSSL

# vim list.txt
..set the configuration...
```

## Usage
```python
# python .\main.py 

# SSL certificate scan start
[1] Pass through proxy: www.google.com
[2] Pass through proxy: account.google.com
[3] Pass through proxy: www.github.com
[4] Pass through proxy: www.naver.com
[5] No pass through proxy: es.stackoverflow.com 
[6] Pass through proxy: devnote_wrong.in
[7] Pass through proxy: not_exits_domain.in
[8] No pass through proxy: accounts.kakao.com 
[9] No pass through proxy: www.youtube.com 
[10] Pass through proxy: developer.mozilla.org

# scan completed
- F:\code\pythonProject\pysslaudit/output/2022-04-17-pysslaudit.log 

# SSL certificate will expire within 90 days.
[1],www.google.com,@@dev1-team,2022-06-20 02:26:06,(expire in 64 days)
[2],account.google.com,@@dev1-team,2022-06-20 01:19:43,(expire in 64 days)
[3],www.naver.com,@@dev2-team,2022-06-08 12:00:00,(expire in 52 days)
[4],es.stackoverflow.com,@@dev2-team,2022-07-05 13:17:41,(expire in 79 days)
[5],www.youtube.com,@Mephisto.act3,2022-06-20 01:19:43,(expire in 64 days)

# SSL certificate scan failed.
[1],2022-04-17 06:39:25,devnote_wrong.in,@@dev2-team,[Errno 11001] getaddrinfo failed
[2],2022-04-17 06:39:26,not_exits_domain.in,@baal.act5,[Errno 11001] getaddrinfo failed
```

## Logs
```
datetime="2022-04-17 06:39:22",no="1",proxy="yes",url="www.google.com",port="443",scan="ok",expire_days="64",before="2022-03-28 02:26:07",after="2022-06-20 02:26:06",subject="/CN=www.google.com",subject_hash="dcb02fe2",issuer="/C=US/O=Google Trust Services LLC/CN=GTS CA 1C3",issuer_hash="c06d5c68",serial="259309961187646395622493212821990173132",signature="sha256WithRSAEncryption",reg_user="@@dev1-team",reg_org="password123456"
datetime="2022-04-17 06:39:23",no="2",proxy="yes",url="account.google.com",port="443",scan="ok",expire_days="64",before="2022-03-28 01:19:44",after="2022-06-20 01:19:43",subject="/CN=*.google.com",subject_hash="f6dbf7a7",issuer="/C=US/O=Google Trust Services LLC/CN=GTS CA 1C3",issuer_hash="c06d5c68",serial="127502721819390281842608657486466279250",signature="sha256WithRSAEncryption",reg_user="@@dev1-team",reg_org="password123456"
datetime="2022-04-17 06:39:24",no="3",proxy="yes",url="www.github.com",port="443",scan="ok",expire_days="333",before="2022-03-15 00:00:00",after="2023-03-15 23:59:59",subject="/C=US/ST=California/L=San Francisco/O=GitHub, Inc./CN=github.com",subject_hash="eff031c4",issuer="/C=US/O=DigiCert Inc/CN=DigiCert TLS Hybrid ECC SHA384 2020 CA1",issuer_hash="ebc232bc",serial="6773885322784420930520969551946270174",signature="ecdsa-with-SHA384",reg_user="@@dev1-team",reg_org="password123456"
datetime="2022-04-17 06:39:24",no="4",proxy="yes",url="www.naver.com",port="443",scan="ok",expire_days="52",before="2020-05-30 00:00:00",after="2022-06-08 12:00:00",subject="/C=KR/ST=Gyeonggi-do/L=Seongnam-si/O=NAVER Corp./CN=*.www.naver.com",subject_hash="568e4dc",issuer="/C=US/O=DigiCert Inc/CN=DigiCert SHA2 Secure Server CA",issuer_hash="85cf5865",serial="7257312108771345729188865094593430825",signature="sha256WithRSAEncryption",reg_user="@@dev2-team",reg_org="password123456"
datetime="2022-04-17 06:39:24",no="5",proxy="no",url="es.stackoverflow.com",port="443",scan="ok",expire_days="79",before="2022-04-06 13:17:42",after="2022-07-05 13:17:41",subject="/CN=*.stackexchange.com",subject_hash="c2e91283",issuer="/C=US/O=Let's Encrypt/CN=R3",issuer_hash="8d33f237",serial="324130112753803123931752308867694203067937",signature="sha256WithRSAEncryption",reg_user="@@dev2-team",reg_org="password123456"
datetime="2022-04-17 06:39:25",no="6",proxy="yes",url="devnote_wrong.in",port="443",scan="failed",expire_days="0",before="None",after="None",subject="[Errno 11001] getaddrinfo failed",subject_hash="None",issuer="None",issuer_hash="None",serial="None",signature="None",reg_user="@@dev2-team",reg_org="password123456"
datetime="2022-04-17 06:39:26",no="7",proxy="yes",url="not_exits_domain.in",port="443",scan="failed",expire_days="0",before="None",after="None",subject="[Errno 11001] getaddrinfo failed",subject_hash="None",issuer="None",issuer_hash="None",serial="None",signature="None",reg_user="@baal.act5",reg_org="password123456"
datetime="2022-04-17 06:39:26",no="8",proxy="no",url="accounts.kakao.com",port="443",scan="ok",expire_days="167",before="2021-09-17 00:00:00",after="2022-09-30 23:59:59",subject="/C=KR/ST=Jeju-do/L=Jeju-si/O=Kakao Corp./CN=*.kakao.com",subject_hash="7948e592",issuer="/C=US/O=DigiCert Inc/OU=www.digicert.com/CN=Thawte TLS RSA CA G1",issuer_hash="feb9fd6",serial="7299096874890431228619409375018135573",signature="sha256WithRSAEncryption",reg_user="@baal.act5",reg_org="password123456"
datetime="2022-04-17 06:39:26",no="9",proxy="no",url="www.youtube.com",port="443",scan="ok",expire_days="64",before="2022-03-28 01:19:44",after="2022-06-20 01:19:43",subject="/CN=*.google.com",subject_hash="f6dbf7a7",issuer="/C=US/O=Google Trust Services LLC/CN=GTS CA 1C3",issuer_hash="c06d5c68",serial="127502721819390281842608657486466279250",signature="sha256WithRSAEncryption",reg_user="@Mephisto.act3",reg_org="password123456"
datetime="2022-04-17 06:39:27",no="10",proxy="yes",url="developer.mozilla.org",port="443",scan="ok",expire_days="200",before="2021-10-05 00:00:00",after="2022-11-02 23:59:59",subject="/CN=developer.mozilla.org",subject_hash="a553daf7",issuer="/C=US/O=Amazon/OU=Server CA 1B/CN=Amazon",issuer_hash="2401d14f",serial="7365265466451665652455072129265632643",signature="sha256WithRSAEncryption",reg_user="@Mephisto.act3",reg_org="password123456"
```
