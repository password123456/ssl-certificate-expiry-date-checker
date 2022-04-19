__author__ = 'https://github.com/password123456/'

import os
import sys
import base64
import importlib
import socket
import ssl
import requests
import OpenSSL
from datetime import datetime, timezone
from urllib.parse import urljoin

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import ocsp
from cryptography.x509.ocsp import OCSPResponseStatus
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID


importlib.reload(sys)

_today_ = datetime.today().strftime('%Y-%m-%d')
_home_path_ = '%s' % os.getcwd()

_scan_list_ = '%s/list.txt' % _home_path_
_scan_logs_ = '%s/output/%s-pysslaudit.log' % (_home_path_, _today_)

_expiration_d_day_ = 90


class Bcolors:
    Black = '\033[30m'
    Red = '\033[31m'
    Green = '\033[32m'
    Yellow = '\033[33m'
    Blue = '\033[34m'
    Magenta = '\033[35m'
    Cyan = '\033[36m'
    White = '\033[37m'
    Endc = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def scan_result_logs(_contents):
    _make_output_dir = '%s/output' % _home_path_
    _mode = 'w'

    if os.path.exists(_make_output_dir):
        if os.path.exists(_scan_logs_):
            _mode = 'a'
    else:
        _mode = 'w'
        os.makedirs(_make_output_dir)

    with open(_scan_logs_, _mode) as fa:
        fa.write('%s' % _contents)
    fa.close()


def get_issuer(cert):
    aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    issuers = [ia for ia in aia if ia.access_method == AuthorityInformationAccessOID.CA_ISSUERS]
    if not issuers:
        raise Exception(f'no issuers entry in AIA')
    return issuers[0].access_location.value


def get_ocsp_server(cert):
    aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    ocsps = [ia for ia in aia if ia.access_method == AuthorityInformationAccessOID.OCSP]
    if not ocsps:
        raise Exception(f'no ocsp server entry in AIA')
    return ocsps[0].access_location.value


def get_issuer_cert(ca_issuer):
    try:
        r = requests.get(ca_issuer)
        if r.status_code == 200:
            _issuer_der = r.content
            _issuer_pem = ssl.DER_cert_to_PEM_cert(_issuer_der)
            _issuer_cert = x509.load_pem_x509_certificate(_issuer_pem.encode('ascii'), default_backend())
        else:
            _issuer_cert = 'fetching issuer cert failed with response status: %s' % r.status_code
    except Exception as e:
        _issuer_cert = '%s' % e
    else:
        r.close()
    return _issuer_cert


def get_oscp_request(ocsp_server, cert, issuer_cert):
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer_cert, SHA256())
    req = builder.build()
    req_path = base64.b64encode(req.public_bytes(serialization.Encoding.DER))
    return urljoin(ocsp_server + '/', req_path.decode('ascii'))


def get_ocsp_cert_status(ocsp_server, cert, issuer_cert):
    try:
        r = requests.get(get_oscp_request(ocsp_server, cert, issuer_cert))
        if r.status_code == 200:
            ocsp_decoded = ocsp.load_der_ocsp_response(r.content)
            if ocsp_decoded.response_status == OCSPResponseStatus.SUCCESSFUL:
                _ocsp_result = '%s' % ocsp_decoded.certificate_status
            else:
                _ocsp_result = '%s' % ocsp_decoded.response_status
        else:
            _ocsp_result = 'OCSPCertStatus.ERROR(fetching ocsp cert status failed with response status: %s' % r.status_code
    except Exception as e:
        _ocsp_result = '%s' % e
    else:
        r.close()
    return _ocsp_result


def check_hostname(_domain):
    try:
        _host_ip = socket.gethostbyname(_domain)
        _check_result = 'ok'
    except Exception as e:
        _check_result = 'failed'
        _host_ip = '%s' % e
    return _check_result, _host_ip


def connect_proxy(_domain):
    _proxy_ip = '54.39.102.233'
    _proxy_port = 80  # port number is a number, not string

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(60.0)
    try:
        proxy_connect = "CONNECT %s:%s HTTP/1.0\r\nConnection: close\r\n\r\n" % (_domain, 443)
        conn.connect((_proxy_ip, _proxy_port))
        conn.send(str.encode(proxy_connect))
        conn.recv(4096)
        _proxy_result = 'opened'
    except Exception as e:
        print("something's wrong with %s:%d. Exception is %s" % (_proxy_ip, _proxy_port, e))
        _proxy_result = 'closed'
    finally:
        conn.close()
    return _proxy_result


def get_cert_info(_domain, _port, _is_ocsp):
    context = ssl.SSLContext()
    conn = socket.create_connection((_domain, _port))
    sock = context.wrap_socket(conn, server_hostname=_domain)
    sock.settimeout(60)

    try:
        certificate = sock.getpeercert(True)
        pem_data = ssl.DER_cert_to_PEM_cert(certificate)
        pem_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_data.encode('ascii'))

        _x509_issuer = pem_cert.get_issuer()
        _x509_subject = pem_cert.get_subject()
        _issuer_str = ''.join('/%s=%s' % (name.decode(), value.decode()) for name, value in _x509_issuer.get_components())
        _subject_str = ''.join('/%s=%s' % (name.decode(), value.decode()) for name, value in _x509_subject.get_components())
        _signature = '%s' % pem_cert.get_signature_algorithm().decode('utf-8')
        _serial = '%s' % pem_cert.get_serial_number()
        _subject_hash = '%x' % pem_cert.get_subject().hash()
        _issuer_hash = '%x' % pem_cert.get_issuer().hash()
        _not_before_obj = datetime.strptime(pem_cert.get_notBefore().decode('utf-8'), '%Y%m%d%H%M%S%z')
        _not_before = '%s' % datetime.strftime(_not_before_obj, '%Y-%m-%d %H:%M:%S')
        _not_after_obj = datetime.strptime(pem_cert.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%S%z')
        _not_after = '%s' % datetime.strftime(_not_after_obj, '%Y-%m-%d %H:%M:%S')
        _certificate_d_days = (_not_after_obj - datetime.now(timezone.utc)).days

        _scan_result = 'ok'
        _ocsp_result = 'failed'
        _socket_staus = 'good'

        _ca_issuer = "None"
        _ocsp_scan_result = "None"

        if _is_ocsp:
            _ocsp_result = 'ok'
            x509_pem_cert = x509.load_pem_x509_certificate(pem_data.encode('ascii'), default_backend())

            _ca_issuer = get_issuer(x509_pem_cert)
            _issuer_cert = get_issuer_cert(_ca_issuer)
            _ocsp_server = get_ocsp_server(x509_pem_cert)
            _ocsp_scan_result = get_ocsp_cert_status(_ocsp_server, x509_pem_cert, _issuer_cert)

        _scan_info = 'before="%s",after="%s",subject="%s",subject_hash="%s",issuer="%s",issuer_hash="%s",' \
                     'serial="%s",signature="%s",ca_issuer="%s",ocsp_status="%s"' \
                     % (_not_before, _not_after, _subject_str, _subject_hash, _issuer_str, _issuer_hash, _serial, _signature, _ca_issuer, _ocsp_scan_result)

    except Exception as e:
        print('%s- SSL socket Error::%s %s%s' % (Bcolors.Yellow, _domain, e, Bcolors.Endc))
        _scan_result = 'failed'
        _ocsp_result = 'failed'
        _socket_staus = '%s' % e
        _certificate_d_days = 0
        _not_after = 0
        _ocsp_scan_result = 'None'

        _scan_info = 'before="None",after="None",subject="%s",subject_hash="None",issuer="None",issuer_hash="None",' \
                     'serial="None",signature="None",ca_issuer="None",ocsp_status="%s"' % (_socket_staus, _ocsp_scan_result)

    finally:
        sock.close()
    return _scan_result, _certificate_d_days, _not_after, _scan_info, _socket_staus, _ocsp_result, _ocsp_scan_result


def get_list():
    if os.path.exists(_scan_list_):
        with open(_scan_list_, 'r') as f:
            _scan_count = 0
            _scan_failed_count = 0
            _expiration_count = 0
            _ocsp_scan_count = 0

            _scan_failed_result = ''
            _expiration_result = ''
            _ocsp_check_result = ''

            print('# SSL certificate scan start')
            for line in f:
                if not line.startswith('#'):
                    if not len(line.strip()) == 0:
                        _is_proxy = line.split(',')[0]
                        _domain = line.split(',')[1]
                        _port = line.split(',')[2]
                        _is_ocsp = line.split(',')[3]
                        _register_user = line.split(',')[4]
                        _register_org = line.split(',')[5].strip()
                        _scan_count = _scan_count + 1

                        _check_result, _host_ip = check_hostname(_domain)
                        if _check_result == 'ok':
                            if int(_is_proxy) == 7749:
                                _proxy_status = connect_proxy(_domain)
                                if _proxy_status == 'opened':
                                    print('(%s)%s [Proxy]%s,  scan_ok, %s' % (_scan_count, Bcolors.Green, Bcolors.Endc, _domain))
                                    _proxy_tunnel = 'yes'
                                    _scan_result, _certificate_d_days, _not_after, _scan_info, _socket_staus,  _ocsp_result, _ocsp_scan_result = get_cert_info(_domain, _port, _is_ocsp)
                                else:
                                    print('(%s)%s [Error]%s,  %s - Something is wrong. Proxy seems down(?)' % (_scan_count, Bcolors.Red, _domain, Bcolors.Endc))
                                    sys.exit(1)
                            else:
                                print('(%s)%s [Normal]%s, scan_ok, %s' % (_scan_count,  Bcolors.Green, Bcolors.Endc, _domain))
                                _proxy_tunnel = 'no'
                                _scan_result, _certificate_d_days, _not_after, _scan_info, _socket_staus, _ocsp_result, _ocsp_scan_result = get_cert_info(_domain, _port, _is_ocsp)

                            _scan_log = 'datetime="%s",no="%s",proxy="%s",url="%s",port="%s",scan="%s",expire_days="%s",%s,reg_user="%s",reg_org="%s"\n' \
                                        % (datetime.today().strftime('%Y-%m-%d %H:%M:%S'), _scan_count, _proxy_tunnel, _domain, _port, _scan_result, _certificate_d_days, _scan_info, _register_user, _register_org)
                        else:
                            print('(%s)%s [Failed]%s, scan_failed, %s - Domain Lookup Failed. ' % (_scan_count,  Bcolors.Yellow, Bcolors.Endc, _domain))
                            if int(_is_proxy) == 7749:
                                _proxy_tunnel = 'yes'
                            else:
                                _proxy_tunnel = 'no'

                            _socket_staus = '%s' % _host_ip
                            _scan_result = 'failed'

                            _scan_info = 'before="None",after="None",subject="%s",subject_hash="None",issuer="None",issuer_hash="None",serial="None",signature="None",ca_issuer="None",ocsp_status="None"' % _socket_staus

                            _scan_log = 'datetime="%s",no="%s",proxy="%s",url="%s",port="%s",scan="%s",expire_days="0",%s,reg_user="%s",reg_org="%s"\n' \
                                        % (datetime.today().strftime('%Y-%m-%d %H:%M:%S'), _scan_count, _proxy_tunnel, _domain, _port, _scan_result, _scan_info, _register_user, _register_org)

                        scan_result_logs(_scan_log)

                        if _scan_result == 'failed':
                            _scan_failed_count = _scan_failed_count + 1
                            _contents = '(%s) %s, %s, %s\n' % (_scan_failed_count, _socket_staus, _domain, _register_user)
                            _scan_failed_result += _contents

                        if _scan_result == 'ok':
                            if _certificate_d_days <= _expiration_d_day_:
                                _expiration_count = _expiration_count + 1
                                _contents = '(%s) [Not Valid in %s-days], [%s], %s, %s\n' \
                                            % (_expiration_count, _certificate_d_days, _not_after, _domain, _register_user)
                                _expiration_result += _contents

                            if _ocsp_result == 'ok':
                                _ocsp_scan_count = _ocsp_scan_count + 1
                                _contents = '(%s) %s, %s\n' % (_ocsp_scan_count, _ocsp_scan_result, _domain)
                                _ocsp_check_result += _contents

            print('\n# scan completed\n- %s%s%s \n' % (Bcolors.Green, _scan_logs_, Bcolors.Endc))

            if _expiration_result:
                print('# Certificate will expire within 90 days.')
                print('%s%s%s' % (Bcolors.Green, _expiration_result, Bcolors.Endc))
                # send to webhook (telegram, slack, SNS)

            if _scan_failed_result:
                print('# Certificate Scan Failed.')
                print('%s%s%s' % (Bcolors.Yellow, _scan_failed_result, Bcolors.Endc))
                # send to webhook (telegram, slack, SNS)

            if _ocsp_check_result:
                print('# OCSP Scan result.')
                print('%s%s%s' % (Bcolors.Green, _ocsp_check_result, Bcolors.Endc))
                # send to webhook (telegram, slack, SNS)

        f.close()
    else:
        print('%s- File not found.! check %s%s' % (Bcolors.Yellow, _scan_list_, Bcolors.Endc))


def main():
    get_list()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print('%s- Exce1ption::%s%s' % (Bcolors.Yellow, e, Bcolors.Endc))
