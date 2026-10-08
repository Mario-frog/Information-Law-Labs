import socket
import time
import csv
from datetime import datetime
from pathlib import Path

HOST, PORT = '127.0.0.1', 5001
LOG = Path(__file__).with_name('results.csv')

def log(protocol, status, elapsed, message):
    exists = LOG.exists() and LOG.stat().st_size > 0
    with LOG.open('a', encoding='utf-8', newline='') as file:
        writer = csv.writer(file)
        if not exists:
            writer.writerow(['timestamp', 'protocol', 'status', 'time_ms', 'message'])
        writer.writerow([datetime.now().isoformat(timespec='seconds'), protocol, status,
                         f'{elapsed * 1000:.3f}', message])

def request(message, timeout=0.5):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        start = time.time()
        client.sendto(message.encode('utf-8'), (HOST, PORT))
        try:
            data, _ = client.recvfrom(65535)
            status, response = 'OK', data.decode('utf-8')
        except socket.timeout:
            status, response = 'TIMEOUT', None
        elapsed = time.time() - start
    log('UDP', status, elapsed, message)
    return status, response, elapsed

if __name__ == '__main__':
    print('UDP single:', request('Hello UDP'))
    print('UDP simulated loss:', request('__DROP__'))
    times = []
    for i in range(100):
        status, response, elapsed = request(f'udp message {i + 1}')
        if status == 'OK':
            times.append(elapsed)
    print(f'UDP: {len(times)}/100 OK, average {sum(times)/len(times)*1000:.3f} ms' if times else 'No UDP replies')
