__author__ = 'https://github.com/password123456/'

import os
import sys
import importlib
import socket
import ssl
import OpenSSL
from datetime import datetime, timezone

importlib.reload(sys)

_today_ = datetime.today().strftime('%Y-%m-%d')
_home_path_ = '%s' % os.getcwd()

_scan_list_ = '%s/list.txt' % _home_path_
_scan_logs_ = '%s/output/%s-pysslaudit.log' % (_home_path_, _today_)

_expiration_ddday_ = 90

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
    

def connect_proxy(_hostname):
    _proxy_ip = '<PROXY IP>'
    _proxy_port = 80  # port number is a number, not string

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        proxy_connect = "CONNECT %s:%s HTTP/1.0\r\nConnection: close\r\n\r\n" % (_hostname, 443)
        conn.settimeout(60.0)
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


def get_ssl_certificate_info(_flag, _hostname, _port):
    try:
        context = ssl.SSLContext()
        with socket.create_connection((_hostname, _port)) as sock:
            with context.wrap_socket(sock, server_hostname=_hostname) as ssock:
                certificate = ssock.getpeercert(True)
                cert = ssl.DER_cert_to_PEM_cert(certificate).encode()
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
                issuer = x509.get_issuer()
                subject = x509.get_subject()

                _issuer_str = ''.join('/%s=%s' % (name.decode(), value.decode()) for name, value in issuer.get_components())
                _subject_str = ''.join('/%s=%s' % (name.decode(), value.decode()) for name, value in subject.get_components())
                _signature = '%s' % x509.get_signature_algorithm().decode('utf-8')
                _serial = '%s' % x509.get_serial_number()
                _subject_hash = '%x' % x509.get_subject().hash()
                _issuer_hash = '%x' % x509.get_issuer().hash()
                _not_before_obj = datetime.strptime(x509.get_notBefore().decode('utf-8'), '%Y%m%d%H%M%S%z')
                _not_before = '%s' % datetime.strftime(_not_before_obj, '%Y-%m-%d %H:%M:%S')
                _not_after_obj = datetime.strptime(x509.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%S%z')
                _not_after = '%s' % datetime.strftime(_not_after_obj, '%Y-%m-%d %H:%M:%S')
                _certificate_d_days = (_not_after_obj - datetime.now(timezone.utc)).days

                _scan_result = 'ok'
                _scan_info = 'before="%s",after="%s",subject="%s",subject_hash="%s",issuer="%s",issuer_hash="%s",serial="%s",signature="%s"' \
                             % (_not_before, _not_after, _subject_str, _subject_hash, _issuer_str, _issuer_hash, _serial, _signature)
                _socket_staus = 'good'
    except socket.error as e:
        #print('%s- SSL socket Error::%s %s%s' % (Bcolors.Yellow, _hostname, e, Bcolors.Endc))
        _scan_result = 'failed'
        _certificate_d_days = 0
        _not_after = 0
        _scan_info = 'before="None",after="None",subject="%s",subject_hash="None",issuer="None",issuer_hash="None",serial="None",signature="None"' % e
        _socket_staus = e

    return _scan_result, _certificate_d_days, _not_after, _scan_info, _socket_staus


def get_list():
    try:
        if os.path.exists(_scan_list_):
            with open(_scan_list_, 'r') as f:
                _scan_list = 0
                _scan_failed_count = 0
                _expiration_count = 0

                _scan_failed_result = ''
                _expiration_result = ''

                print('# SSL certificate scan start')
                for line in f:
                    if not line.startswith('#'):
                        if not len(line.strip()) == 0:
                            _flag = line.split(',')[0]
                            _domain = line.split(',')[1]
                            _port = line.split(',')[2]
                            _register_user = line.split(',')[3]
                            _register_org = line.split(',')[4].strip()
                            _scan_list = _scan_list + 1
                            if int(_flag) == 7749:
                                _proxy_status = connect_proxy(_domain)
                                if _proxy_status == 'opened':
                                    print('[%s] Pass through proxy: %s' % (_scan_list, _domain))
                                    _proxy_tunnel = 'yes'
                                    _scan_result, _certificate_d_days, _not_after, _scan_info, _socket_staus = get_ssl_certificate_info(_flag, _domain, _port)
                                else:
                                    print('%s- [Error] Something is wrong. Proxy is down.%s' % (Bcolors.Yellow, Bcolors.Endc))
                                    sys.exit(1)
                            else:
                                print('[%s] No pass through proxy: %s ' % (_scan_list, _domain))
                                _proxy_tunnel = 'no'
                                _scan_result, _certificate_d_days, _not_after, _scan_info, _socket_staus = get_ssl_certificate_info(_flag, _domain, _port)

                            _scan_log = 'datetime="%s",no="%s",proxy="%s",url="%s",port="%s",scan="%s",expire_days="%s",%s,reg_user="%s",reg_org="%s"\n' \
                                        % (datetime.today().strftime('%Y-%m-%d %H:%M:%S'), _scan_list, _proxy_tunnel,
                                           _domain, _port, _scan_result, _certificate_d_days, _scan_info, _register_user, _register_org)

                            scan_result_logs(_scan_log)

                            if _scan_result == 'failed':
                                _scan_failed_count = _scan_failed_count + 1
                                _contents = '[%s],%s,%s,%s,%s\n' % (_scan_failed_count, datetime.today().strftime('%Y-%m-%d %H:%M:%S'),
                                                                  _domain, _register_user, _socket_staus)
                                _scan_failed_result += _contents

                            if _scan_result == 'ok':
                                if _certificate_d_days <= _expiration_ddday_:
                                    _expiration_count = _expiration_count + 1
                                    _contents = '[%s],%s,%s,%s,(expire in %s days)\n' \
                                                % (_expiration_count, _domain, _register_user, _not_after, _certificate_d_days)
                                    _expiration_result += _contents

                print('\n# scan completed\n- %s%s%s \n' % (Bcolors.Cyan, _scan_logs_, Bcolors.Endc))

                if _expiration_result:
                    print('# SSL certificate will expire within 90 days.')
                    print('%s%s%s' % (Bcolors.Green, _expiration_result, Bcolors.Endc))
                    # send to webhook (telegram, slack, line)

                if _scan_failed_result:
                    print('# SSL certificate scan failed.')
                    print('%s%s%s' % (Bcolors.Yellow, _scan_failed_result, Bcolors.Endc))
                    # send to webhook (telegram, slack, line)
            f.close()

        else:
            print('%s- File not found.! check %s%s' % (Bcolors.Yellow, _scan_list_, Bcolors.Endc))
    except Exception as e:
        print('%s- Exception::%s%s' % (Bcolors.Yellow, e, Bcolors.Endc))


def main():
    get_list()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print('%s- Exception::%s%s' % (Bcolors.Yellow, e, Bcolors.Endc))
