import socket

HOST = '127.0.0.1'
PORT = 65432


def main():
    message = input('Enter message: ')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((HOST, PORT))
        client.sendall(message.encode('utf-8'))
        response = client.recv(4096).decode('utf-8')
    print('Server response:', response)


if __name__ == '__main__':
    main()
