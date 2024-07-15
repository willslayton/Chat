import socket
import threading
import datetime
import sys

HOST = "localhost"
PORT = 9999
DATA_SIZE = 128

class client:
    def __init__(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((HOST, PORT))
        
        self.is_online = True
        self.username = input("Please enter username >   ")

        self.read_thread = threading.Thread(target=self.recieve)
        self.read_thread.start()

        self.write_thread = threading.Thread(target=self.send)
        self.write_thread.start()
    
    def recieve(self):
        password = "passwd"
        self.client.send(f"LOGI {self.username}:{password}\r\n".encode())

        print(self.client.recv(DATA_SIZE).decode())
        self.client.send("REQU".encode())

        while self.is_online:
            try:
                message = self.client.recv(DATA_SIZE).decode()

                for line in message.split("\r\n"):
                    match line[:4]:
                        case "PING":
                            line[1] = 'O'
                            self.client.send(line.encode())
                        case "WELC":
                            print(line)
                            self.username = line[5:]
                            
                        case "MESG":
                            content = line[5:].split(':')
                            print(f"[{content[0]}]: {''.join(content[1:])}")

            except:
                self.client.close()
                break
    
    def send(self):
        while self.is_online:
            message = input("")
            sys.stdout.write("\r")
            if len(message) > 1:
                self.client.send(f"MESG {message}".encode())

client()