from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread


clients = {}        #client socket:name
addresses = {}      #client socket:address

HOST = '127.0.0.1'      #Predefined Information
PORT = 33000
BUFSIZ = 1024
ADDR = (HOST, PORT)

SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)


def send_message(message, client_socket):
    message_length = str(len(message)).zfill(10)
    client_socket.send(message_length.encode('utf-8') + message.encode('utf-8'))


def receive_message(client_socket):
    message_prefix = client_socket.recv(10).decode('utf-8')
    if not message_prefix:
        return None  

    try:
        message_length = int(message_prefix)
    except ValueError:
        print("Invalid message length prefix")
        return None

    message = client_socket.recv(message_length).decode('utf-8')
    return message



def accept_incoming_connections():
    """Sets up handling for incoming clients."""
    while True:
        client, client_address = SERVER.accept()
        addresses[client] = client_address
        Thread(target=handle_client, args=(client,)).start()



def extract_username(message, clients):
    if message[0] == '@' and ' ' in message:
        username = message[1:message.find(' ')]
        message = message[message.find(' ')+1:]
        
        if username in clients.values() :
            return username, message
            
        else :
            return (False, message)

    elif message[0] == '@' and ' ' not in message:
        username = message[1:]
        message = ''
        if username in clients.values() :
            return username, message
            
        else :
            return (False, message)
    else:
        return (False, message)




def handle_client(client):
    """Handles a single client connection."""

    name = receive_message(client)
    if name  in list(clients.values()):
        send_message(":::USERNAME_ALREADY_IN_USE:::", client)
        client.close()
        return
    
    print(f"{name} joined the server")
    welcome = '[SERVER]: Welcome %s! If you ever want to quit, type {quit} to exit.' % name
    send_message(welcome, client)
    
    msg = "[SERVER] : %s has joined the chat!" % name
    broadcast(msg, client)
    
    clients[client] = name

    update_active_user()

    while True:
        try:
            message = receive_message(client)

            if msg != bytes("{quit}", "utf-8"):
                to_user, only_message = extract_username(message, clients)

                if to_user is False:

                    print(f"{name} sent to all clients: {only_message}")
                    broadcast(f"{name} : {only_message}", client)
                else:

                    print(f"{name} sent to {to_user}: {only_message}")
                    send_direct_message(name, to_user, only_message)

            else:
                client.close()
                break

        except :
            client.close()
            break

    broadcast("[SERVER] : User %s has left the chat." % name, client)
    del clients[client]
    print(f"Active Users: {list(clients.values())}")
    update_active_user()
    



def update_active_user():
    active_user = ':::CONNECTED_USERS:::' + str(list(clients.values()))
    for client_socket in clients:
        send_message(active_user, client_socket)




def broadcast(message, sender_socket):
    for client_socket in clients:
        if client_socket != sender_socket:
            try:
                send_message(message,client_socket)
            except socket.error:
                
                pass


def send_direct_message(sender_name, recipient_name, only_message):
    
    only_message = f"{sender_name} : {only_message}"
    for client_socket, name in clients.items():
        if name == recipient_name:
            try:
                send_message(only_message,client_socket)
            except :
                
                pass


if __name__ == "__main__":
    SERVER.listen(5)
    print("Waiting for connection...")
    ACCEPT_THREAD = Thread(target = accept_incoming_connections)
    ACCEPT_THREAD.start()
    ACCEPT_THREAD.join()
    SERVER.close()
    
