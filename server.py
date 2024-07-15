import socket
import threading
import sqlite3
import logging
import datetime
import hashlib

HOST = "localhost"
PORT = 9999
DATA_SIZE = 1024
DB_PATH = "./chat.db"


# Models
class Message:
    def __init__(self, author, content):
        self.id = None
        self.author = author
        self.content = content
        self.timestamp = Helper.current_timestamp()

class User:
    def __init__(self, id, username):
        self.id = id
        self.username = username


class Server:

    def __init__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((HOST, PORT))
        self.clients = {}
        self.database = Database()

    def start(self):
        self.server.listen()
        print("Server is online!")

        while True:
            client, address = self.server.accept()
            thread = threading.Thread(target=self.handle, args=(client, address))
            thread.start()

    

    def handle(self, client, address):
        print(f"<CONNECTED: {address}>")
        
        authenticated = False
        try:
            while message := client.recv(DATA_SIZE).decode():
                for line in message.split("\r\n"):
                    print(f"[{address[0]}:{address[1]}] {line}")
                    if not authenticated:
                        authenticated = self.login(client, line)
                    else:
                        self.parse(client, line)
        
        except ConnectionResetError:
            print(f"<DISCONNECT: {address}, THREADS: {threading.active_count() - 1}>")
            del self.clients[client]
            client.close()
            return
    
    def broadcast(self, message):
        for client in self.clients.keys():
            client.send(message)

    def parse(self, client, line):
        match(line[:4]):
            case "PING":
                line[1] = 'O'
                client.send(line.encode())
            case "MESG":
                try:
                    self.database.create_message(Message(self.clients[client], line[5:]))
                    self.broadcast(f"MESG {self.clients[client]}: {line[5:]}".encode())
                except:
                    print("ERRO Could not send message.")
            case "LOGO":
                del self.clients[client]
                client.close()
            case "REQU":
                for message in self.database.get_history():
                    client.send(f"MESG {message[1]}: {message[3]}\r\n".encode())

    def login(self, client, line):
        if line[:4] == "LOGI":
            user, passw = line[5:].split(":")
            user = self.database.get_user(user)
            self.clients[client] = User(user[0], user[1])
            return True

        else:
            client.send("ERRO Not logged in.\r\n".encode())
            return False

class Database:

    class Connection:
        def __init__(self):
            self.connection = sqlite3.connect(DB_PATH)
        def __enter__(self):
            self.cursor = self.connection.cursor()
            return self.cursor
        def __exit__(self, exception_type, exception_value, traceback):
            if exception_type is not None:
                print(f"{exception_type}: {exception_value}\n{traceback}")
            self.connection.commit()
            self.connection.close()

    def __init__(self):

        with self.Connection() as cursor:
            # User tables
            cursor.execute("CREATE TABLE IF NOT EXISTS Users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, title TEXT DEFAULT NULL, joined INT)")
            cursor.execute("CREATE TABLE IF NOT EXISTS Passwords (id INTEGER, value BLOB, FOREIGN KEY (id) REFERENCES Users(id))")
            #cursor.execute("CREATE TABLE IF NOT EXISTS Connections (id INTEGER, osu INTEGER, discord INTEGER, twitch INTEGER, FOREIGN KEY (id) REFERENCES Users(id))")
            cursor.execute("CREATE TABLE IF NOT EXISTS UserStats (id INTEGER, messages INTEGER, active INT, FOREIGN KEY (id) REFERENCES Users(id))")

            # Group tables
            #cursor.execute("CREATE TABLE IF NOT EXISTS Groups (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)")
            #cursor.execute("CREATE TABLE IF NOT EXISTS Membership (id INTEGER, group INTEGER, FOREIGN KEY (id) REFERENCES Users(id), FOREIGN KEY (group) REFERENCES Groups(id))")

            # Chat tables
            cursor.execute("CREATE TABLE IF NOT EXISTS Channels (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, motd TEXT)")
            cursor.execute("CREATE TABLE IF NOT EXISTS Messages (id INTEGER PRIMARY KEY AUTOINCREMENT, author INTEGER, channel INTEGER, timestamp INTEGER, content TEXT, FOREIGN KEY (author) REFERENCES Users(id), FOREIGN KEY (channel) REFERENCES Channels(id))")

            # Perms (integer bitwise table)
            #cursor.execute("CREATE TABLE IF NOT EXISTS Permissions (group INTEGER, channel INTEGER, permission INTEGER, FOREIGN KEY (group) REFERENCES Groups(id), FOREIGN KEY (channel) REFERENCES Channels(id))")
            self.__init_populate__()
    def __init_populate__(self):
        with self.Connection() as cursor:
            cursor.execute("INSERT INTO Users (id, name, title, joined) VALUES (?, ?, ?, ?)", (1, "Server", "w00t p00t", Helper.current_timestamp()))
            cursor.execute("INSERT INTO Passwords (id, value) VALUES (?, ?)", (1, Helper.hash("Wowee!")))
            cursor.execute("INSERT INTO UserStats (id, messages, active) VALUES (?, ?, ?)", (1, 0, Helper.current_timestamp()))

            cursor.execute("INSERT INTO Channels (id, name, motd) VALUES (?, ?, ?)", (1, "general", "Just a general channel..."))
            cursor.execute("INSERT INTO Channels (id, name, motd) VALUES (?, ?, ?)", (2, "secret", "Just a secret channel..."))

            cursor.execute("INSERT INTO Messages (author, channel, timestamp, content) VALUES (?, ?, ?, ?)", (1, 1, Helper.current_timestamp(), "general channel..."))
            cursor.execute("INSERT INTO Messages (author, channel, timestamp, content) VALUES (?, ?, ?, ?)", (1, 2, Helper.current_timestamp(), "not so general channel..."))

            cursor.connection.commit()
        

    def create_user(self, username: str, password: bytes):
        now = Helper.current_timestamp()
        with self.Connection() as cursor:
            cursor.execute("INSERT INTO Users (name, joined) VALUES (?, ?)", (username, now))
            cursor.connection.commit()
            cursor.execute("SELECT id FROM Users WHERE name = ?", (username,))
            id = cursor.fetchone()
            cursor.execute("INSERT INTO Passwords (id, value) VALUES (?, ?)", (id, password))
            cursor.execute("INSERT INTO Connections (id) VALUES (?)", (id,))
            cursor.execute("INSERT INTO UserStats (id, messages, active) VALUES (?, ?)", (id, 0, now))
            cursor.connection.commit()

    def create_message(self, message):
        with self.Connection() as cursor:
            cursor.execute("INSERT INTO Messages (author, timestamp, content) VALUES (?, ?, ?)", (message.author, message.timestamp, message.content))
            cursor.connection.commit()
            cursor.execute("SELECT id FROM Messages WHERE author = ? AND timestamp = ?")

    def create_group(self, groupname):
        with self.Connection() as cursor:
            cursor.execute("INSERT INTO Groups (name) VALUES (?)", (groupname))
            cursor.connection.commit()
            cursor.execute("SELECT id FROM Messages WHERE author = ? AND timestamp = ?")
    
    def create_channel(self, channelname, ):
        with self.Connection() as cursor:
            cursor.execute("INSERT INTO Channels (name) VALUES (?)", (channelname))
            cursor.connection.commit()
            cursor.execute("SELECT id FROM Messages WHERE author = ? AND timestamp = ?")

    

    def get_history(self, limit=10):
        with self.Connection() as cursor:
            cursor.execute("SELECT * FROM Messages ORDER BY id DESC LIMIT ?", (limit,))
            return cursor.fetchall()
    
    def get_user(self, user):
        if isinstance(user, str):
            command = "SELECT * FROM Users WHERE username = ?"
        elif isinstance(user, int):
            command = "SELECT * FROM Users WHERE id = ?"
        with self.Connection() as cursor:
            cursor.execute(command, (user,))
            return cursor.fetchone()

class Helper:

    def current_timestamp(self):
        return int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    
    def hash(text):
        sha = hashlib.new("SHA512")
        sha.update(text.encode())
        return sha.hexdigest()




serv = Server()

serv.start()