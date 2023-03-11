import socket

server_ip = "127.0.0.2"
server_port = 80


def start_server():
    # create server socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # bind the socket to server host and port
    server_sock.bind((server_ip, server_port))
    print("[+]server socket created")
    # start listening for new connection only one client at a time
    server_sock.listen(1)
    print("[+]listening for connection")

    while True:
        # accept new connection
        client_sock, client_add = server_sock.accept()
        print(f'connection made with :{client_add}')

        # receive the client's packet and decode it to string
        request = client_sock.recv(1024).decode('utf-8')

        # check if its a get http request
        if 'GET' in request:
            print("received GET request")
            # check if the client requested the img1
            filename = request.split()[1][1:]
            # open the requested image and send it to the client as http response
            with open(filename, 'rb') as file:
                img_data = file.read()
                response = b'HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\n\r\n' + img_data
                client_sock.sendall(response)
                print("response sent successfully.")
                # close socket
                client_sock.close()
                print("[+]client_sock closed")
                break
    # close socket
    server_sock.close()
    print("[+]server_sock closed")

if __name__ == '__main__':
    start_server()
