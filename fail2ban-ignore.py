#!env python3

import os
import sys
import glob
import ipaddress
import asyncio
import socket
import signal
import pickle
from datetime import datetime

DATA_DIR = '/etc/fail2ban/ignoreip.d'
RUN_DIR = '/var/run/fail2ban'
UNIXSOCK = '/'.join([RUN_DIR, 'fail2ban-ignore.sock'])
PID_FILE = '/'.join([RUN_DIR, 'fail2ban-ignore.pid'])
CACHE_TTL = 3600
CACHE_LOCK = asyncio.Lock()

def process_args(argv):
    if len(argv) != 2:
        sys.stderr.write(
            "Please provide a single IP as an argument. Got: %s\n" % (argv[1:])
        )
        sys.exit(2)

    ip = argv[1]
    if not is_valid_ip(ip):
        sys.stderr.write(
            "Argument must be a single valid IP. Got: %s\n" % ip
        )
        sys.exit(3)
    return ip

is_valid_ip = lambda x: all([
    p <= 255 and (p > 0 if i == 0 else p >= 0)
    for i, p in enumerate(map(int, x.split(".")))
])

def ip_info(cidr):
    if '/' not in cidr:
        cidr = '%s/32' % cidr

    n = ipaddress.ip_network(cidr, strict=False)
    return int(n.network_address), int(n.broadcast_address)

def ip_to_int(ip):
    o = list(map(int, ip.split(".")))
    res = (16777216 * o[0]) + (65536 * o[1]) + (256 * o[2]) + o[3]
    return res

def get_config_files():
    conf_files = glob.glob('/'.join((DATA_DIR, '*.conf')))
    for conf_file in conf_files:
        yield conf_file

def get_ignore_record():
    for conf_file in get_config_files():
        with open(conf_file, 'r') as f:
            for rec in f.readlines():
                if not rec:
                    continue
                if rec.startswith('#'):
                    continue
                yield rec.split()[0]

def get_ips():
    ips = set()
    for rec in get_ignore_record():
        ips.add(ip_info(rec))
    return list(ips)

def is_ignored(ips, ip):
    ip = ip_to_int(ip)
    for min_addr, max_addr in ips:
        if min_addr <= ip <= max_addr:
            return True
    return False

def fix_cache():
    global ips, cache

    now = datetime.now().timestamp()
    yield from CACHE_LOCK
    try:
        for ip, result in cache.items():
            _, ts = result
            if now - ts > CACHE_TTL:
                del cache[ip]
                continue
            if is_ignored(ips, ip) and result == 'BLOCK':
                cache[ip] = ('OK', now)
            if not is_ignored(ips, ip) and result == 'OK':
                cache[ip] = ('BLOCK', now)
    except Exception as e:
        print(str(e))
    finally:
        CACHE_LOCK.release()

def unban_ips():
    _at = datetime.now().timestamp()
    ips = get_ips()
    unbanned = unban()
    if isinstance(unbanned, list):
        res = 'Unbanned {} IPs'.format(len(unbanned))
    else:
        res = unbanned
    _at = datetime.now().timestamp() - _at
    return '{}. Done in {:.4f} sec. {}'.format(res, _at, server_stat())

def unban():
    global ips
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    unbanned = []
    try:
        s.connect('/var/run/fail2ban/fail2ban.sock')
        for i, j in ips:
            if i != j:
                continue
            ip = str(ipaddress.IPv4Address(i))
            cmd = ['unban', ip]
            if s.send(pickle.dumps(cmd, 0) + b"<F2B_END_COMMAND>"):
                unbanned.append(ip)
    except ConnectionRefusedError as e:
        return "Failed to connect to fail2ban server!"
    finally:
        s.close()
    return unbanned

def remove_unix_socket(path):
    import os, stat
    try:
        if stat.S_ISSOCK(os.stat(path).st_mode):
            os.unlink(path)
    except (FileNotFoundError, NotADirectoryError):
        pass

def server_stat():
    global ips, cache, start, total
    now = datetime.now().timestamp()
    speed = total / (now - start)
    fmt = 'REQS: {:d} CACHED: {:d} WHITE: {:d} PACE: {:.3f} req/sec'
    return fmt.format(total, len(cache), len(ips), speed)

def reload_whitelist():
    _at = datetime.now().timestamp()
    ips = get_ips()
    fix_cache()
    _at = datetime.now().timestamp() - _at
    return 'Reloaded in {:.4f} sec. {}'.format(_at, server_stat())

def whitelist_lookup(ip):
    global ips, cache

    # looking for IP in whitelist
    yield from CACHE_LOCK
    try:
        now = datetime.now().timestamp()
        response, ts = cache.get(ip, (None, now))
        if response and ts and now - ts > CACHE_TTL:
            # expire cache record after 1 hr
            del cache[ip]
            response = None
        if not response:
            response = 'OK' if is_ignored(ips, ip) else 'BLOCK'
            cache[ip] = (response, now)
            print('IP {} should be added to cache with {}, the result: {}'.format(
                ip, response, str(cache[ip])
            ))
    except Exception as e:
        response = 'Bad request: %s' % str(e)
    finally:
        CACHE_LOCK.release()
    return response

@asyncio.coroutine
def handle_client(reader, writer):
    global total

    request = None
    while request != 'quit':
        total += 1
        request = yield from reader.read(255)
        request = request.decode('utf8')
        if not request:
            break
        request = request.strip()
        try:
            if request == 'reload':
                response = reload_whitelist()
            elif request == 'unban':
                response = unban_ips()
            elif request == 'stat':
                response = server_stat()
            else:
                response = whitelist_lookup(request)

            #print('Got: %s => %s' % (request, response))
            writer.write('{}\n'.format(response).encode('utf8'))
            yield from writer.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
    writer.close()

def print_usage():
    print("""
    Usage:
        ignoredb-update - update database with ignored IPs
        ignoredb-check <IP> - check the IP for presense in the whitelist
    """
    )

def pid_file_create(pid):
    with open(PID_FILE, 'w') as pid_file:
        pid_file.write(str(pid))

def pid_file_remove():
    try:
        os.remove(PID_FILE)
    except OSError:
        pass

def run_server():
    pid_file_create(os.getpid())

    def stop_loop():
        loop.stop()

    loop = asyncio.get_event_loop()
    for signame in ('SIGINT', 'SIGTERM'):
        loop.add_signal_handler(getattr(signal, signame), stop_loop)

    remove_unix_socket(UNIXSOCK)
    coro = asyncio.start_unix_server(handle_client, path=UNIXSOCK, loop=loop)
    server = loop.run_until_complete(coro)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    print(server_stat())
    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()

    pid_file_remove()


if __name__ == '__main__':

    if len(sys.argv) > 1 and '--help' in sys.argv:
        print_usage()
        sys.exit()

    if os.path.exists(PID_FILE):
        print('Error: PID file %s is present! Exiting...' % PID_FILE)
        print_usage()
        sys.exit()

    ips = get_ips()
    cache = {}
    start = datetime.now().timestamp()
    total = 0
    run_server()