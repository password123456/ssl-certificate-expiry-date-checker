# ssl_certificate_expiry_date_checker
![made-with-python][made-with-python]
![Python Versions][pyversion-button]
[![Hits](https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2Fpassword123456%2Fhit-counter&count_bg=%2379C83D&title_bg=%23555555&icon=&icon_color=%23E7E7E7&title=hits&edge_flat=false)](https://hits.seeyoufarm.com)


[pyversion-button]: https://img.shields.io/pypi/pyversions/Markdown.svg
[made-with-python]: https://img.shields.io/badge/Made%20with-Python-1f425f.svg

- Find out which cerificate will expire and need to renew.
- Find various information from scan result (expire date, issuer, signature, serial number...)
- If you are ssl cerificate manager in your organization, collect the list from your coworker, teams, and check the expire date of the certificates.
- custom notify when SSL certificates are about to expire with a detail result (WEBHOOK, Telegram-Bot, Slack...)
- The difference from other similar tools, optionally choose to use proxy by domain. for example, there's a system in the restricted private enviroment network and have to scan, you may have to use proxy.
- In the configuraion you can set the proxy ip/port and can set which domains must pass through the proxy system in the list.txt.
- If you have a various log analyzer, you can collect logs and do what you want to more.

# Features
- scan ssl_certificate and get information (before_date, after_date, issuer, issuer_hash, serial, signatures)
- set pass through the proxy or not by domain.
- ocsp valid check by domain.
- verify ssl_certificates that will be expire within set days.
- create custom logs and can query.

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
(1) [Proxy],  scan_ok, www.google.com
(2) [Proxy],  scan_ok, account.google.com
(3) [Proxy],  scan_ok, www.github.com
(4) [Proxy],  scan_ok, www.naver.com
(5) [Normal], scan_ok, es.stackoverflow.com
(6) [Failed], scan_failed, devnote_wrong.in - Domain Lookup Failed. 
(7) [Failed], scan_failed, not_exits_domain.in - Domain Lookup Failed. 
(8) [Normal], scan_ok, www.youtube.com
(9) [Proxy],  scan_ok, developer.mozilla.org

# scan completed
- F:\code\pythonProject\pysslaudit2/output/2022-04-20-pysslaudit.log 

# Certificate will expire within 90 days.
(1) [Not Valid in 61-days], [2022-06-20 02:26:06], www.google.com, @@dev1-team
(2) [Not Valid in 61-days], [2022-06-20 01:19:43], account.google.com, @@dev1-team
(3) [Not Valid in 49-days], [2022-06-08 12:00:00], www.naver.com, @@dev2-team
(4) [Not Valid in 76-days], [2022-07-05 13:17:41], es.stackoverflow.com, @@dev2-team
(5) [Not Valid in 61-days], [2022-06-20 01:19:43], www.youtube.com, @Mephisto.act3

# Certificate Scan Failed.
(1) [Errno 11001] getaddrinfo failed, devnote_wrong.in, @@dev2-team
(2) [Errno 11001] getaddrinfo failed, not_exits_domain.in, @baal.act5

# OCSP Scan result.
(1) OCSPResponseStatus.MALFORMED_REQUEST, www.google.com
(2) OCSPResponseStatus.MALFORMED_REQUEST, account.google.com
(3) OCSPCertStatus.GOOD, www.github.com
(4) OCSPCertStatus.GOOD, www.naver.com
(5) OCSPResponseStatus.UNAUTHORIZED, es.stackoverflow.com
(6) OCSPResponseStatus.MALFORMED_REQUEST, www.youtube.com
(7) OCSPCertStatus.GOOD, developer.mozilla.org
```

## Logs
```
datetime="2022-04-20 00:44:11",no="1",proxy="yes",url="www.google.com",port="443",scan="ok",expire_days="61",before="2022-03-28 02:26:07",after="2022-06-20 02:26:06",subject="/CN=www.google.com",subject_hash="dcb02fe2",issuer="/C=US/O=Google Trust Services LLC/CN=GTS CA 1C3",issuer_hash="c06d5c68",serial="259309961187646395622493212821990173132",signature="sha256WithRSAEncryption",ca_issuer="http://pki.goog/repo/certs/gts1c3.der",ocsp_status="OCSPResponseStatus.MALFORMED_REQUEST",reg_user="@@dev1-team",reg_org="password123456"
datetime="2022-04-20 00:44:12",no="2",proxy="yes",url="account.google.com",port="443",scan="ok",expire_days="61",before="2022-03-28 01:19:44",after="2022-06-20 01:19:43",subject="/CN=*.google.com",subject_hash="f6dbf7a7",issuer="/C=US/O=Google Trust Services LLC/CN=GTS CA 1C3",issuer_hash="c06d5c68",serial="127502721819390281842608657486466279250",signature="sha256WithRSAEncryption",ca_issuer="http://pki.goog/repo/certs/gts1c3.der",ocsp_status="OCSPResponseStatus.MALFORMED_REQUEST",reg_user="@@dev1-team",reg_org="password123456"
datetime="2022-04-20 00:44:13",no="3",proxy="yes",url="www.github.com",port="443",scan="ok",expire_days="330",before="2022-03-15 00:00:00",after="2023-03-15 23:59:59",subject="/C=US/ST=California/L=San Francisco/O=GitHub, Inc./CN=github.com",subject_hash="eff031c4",issuer="/C=US/O=DigiCert Inc/CN=DigiCert TLS Hybrid ECC SHA384 2020 CA1",issuer_hash="ebc232bc",serial="6773885322784420930520969551946270174",signature="ecdsa-with-SHA384",ca_issuer="http://cacerts.digicert.com/DigiCertTLSHybridECCSHA3842020CA1-1.crt",ocsp_status="OCSPCertStatus.GOOD",reg_user="@@dev1-team",reg_org="password123456"
datetime="2022-04-20 00:44:14",no="4",proxy="yes",url="www.naver.com",port="443",scan="ok",expire_days="49",before="2020-05-30 00:00:00",after="2022-06-08 12:00:00",subject="/C=KR/ST=Gyeonggi-do/L=Seongnam-si/O=NAVER Corp./CN=*.www.naver.com",subject_hash="568e4dc",issuer="/C=US/O=DigiCert Inc/CN=DigiCert SHA2 Secure Server CA",issuer_hash="85cf5865",serial="7257312108771345729188865094593430825",signature="sha256WithRSAEncryption",ca_issuer="http://cacerts.digicert.com/DigiCertSHA2SecureServerCA.crt",ocsp_status="OCSPCertStatus.GOOD",reg_user="@@dev2-team",reg_org="password123456"
datetime="2022-04-20 00:44:14",no="5",proxy="no",url="es.stackoverflow.com",port="443",scan="ok",expire_days="76",before="2022-04-06 13:17:42",after="2022-07-05 13:17:41",subject="/CN=*.stackexchange.com",subject_hash="c2e91283",issuer="/C=US/O=Let's Encrypt/CN=R3",issuer_hash="8d33f237",serial="324130112753803123931752308867694203067937",signature="sha256WithRSAEncryption",ca_issuer="http://r3.i.lencr.org/",ocsp_status="OCSPResponseStatus.UNAUTHORIZED",reg_user="@@dev2-team",reg_org="password123456"
datetime="2022-04-20 00:44:14",no="6",proxy="yes",url="devnote_wrong.in",port="443",scan="failed",expire_days="0",before="None",after="None",subject="[Errno 11001] getaddrinfo failed",subject_hash="None",issuer="None",issuer_hash="None",serial="None",signature="None",ca_issuer="None",ocsp_status="None",reg_user="@@dev2-team",reg_org="password123456"
datetime="2022-04-20 00:44:14",no="7",proxy="yes",url="not_exits_domain.in",port="443",scan="failed",expire_days="0",before="None",after="None",subject="[Errno 11001] getaddrinfo failed",subject_hash="None",issuer="None",issuer_hash="None",serial="None",signature="None",ca_issuer="None",ocsp_status="None",reg_user="@baal.act5",reg_org="password123456"
datetime="2022-04-20 00:44:14",no="8",proxy="no",url="www.youtube.com",port="443",scan="ok",expire_days="75",before="2022-04-11 08:31:00",after="2022-07-04 08:30:59",subject="/CN=*.google.com",subject_hash="f6dbf7a7",issuer="/C=US/O=Google Trust Services LLC/CN=GTS CA 1C3",issuer_hash="c06d5c68",serial="173112468218162436128115961282197492034",signature="sha256WithRSAEncryption",ca_issuer="http://pki.goog/repo/certs/gts1c3.der",ocsp_status="OCSPResponseStatus.MALFORMED_REQUEST",reg_user="@Mephisto.act3",reg_org="password123456"
datetime="2022-04-20 00:44:15",no="9",proxy="yes",url="developer.mozilla.org",port="443",scan="ok",expire_days="197",before="2021-10-05 00:00:00",after="2022-11-02 23:59:59",subject="/CN=developer.mozilla.org",subject_hash="a553daf7",issuer="/C=US/O=Amazon/OU=Server CA 1B/CN=Amazon",issuer_hash="2401d14f",serial="7365265466451665652455072129265632643",signature="sha256WithRSAEncryption",ca_issuer="http://crt.sca1b.amazontrust.com/sca1b.crt",ocsp_status="OCSPCertStatus.GOOD",reg_user="@Mephisto.act3",reg_org="password123456"
```
