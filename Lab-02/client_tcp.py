import socket
import time
from client_udp import log
HOST, PORT = '127.0.0.1', 5002

def request(message):
    start = time.time()
    try:
        with socket.create_connection((HOST, PORT), timeout=1) as client:
            client.sendall(message.encode('utf-8'))
            reply = client.recv(65535).decode('utf-8')
        status = 'OK'
    except (OSError, socket.timeout) as exc:
        status, reply = 'ERROR', str(exc)
    elapsed = time.time() - start
    log('TCP', status, elapsed, message)
    return status, reply, elapsed

if __name__ == '__main__':
    print('TCP single:', request('Hello TCP'))
    times = []
    for i in range(100):
        status, response, elapsed = request(f'tcp message {i + 1}')
        if status == 'OK':
            times.append(elapsed)
    print(f'TCP: {len(times)}/100 OK, average {sum(times)/len(times)*1000:.3f} ms' if times else 'No TCP replies')
