import socket
import requests

proxy_ip = "127.0.0.1"
proxy_port = 80
server_ip = "127.0.0.2"
server_port = 80


def start_proxy():
    # create server socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # bind the socket to server host and port
    server_sock.bind((proxy_ip, proxy_port))
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

        # check if its a GET http request
        if 'GET' in request:
            print("received GET request")
            # check if is it request for img1
            filename = request.split()[1][1:]
            if filename == 'img1.jpg':
                # make a request from server for the image
                new_url = f'http://{server_ip}:{server_port}/{filename}'
                response = requests.get(new_url)
                # check if we received the correct response
                if response.status_code == 200:
                    # create a response to send to the client
                    reply = b'HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\n\r\n' + response.content
                    client_sock.sendall(reply)
                    print("response sent successfully.")
                else:
                    print("didnt get the image successfully")
                client_sock.close()
                break
            else:
                print("received other type of request")
    server_sock.close()


if __name__ == '__main__':
    start_proxy()
