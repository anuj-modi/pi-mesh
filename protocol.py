import os
import yaml
import sys
import select
from queue import Queue
import time
from enum import IntEnum
import threading
import bson
import socket
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

TIMEOUT = 5


class ConnectionState(IntEnum):
    CLIENT_HELLO = 1,
    SERVER_HELLO = 2,
    CLIENT_CIPHER_SENT = 3,
    SERVER_CIPHER_SENT = 4,
    ACTIVE = 5,
    CLOSED = 6


class Connection:
    def __init__(self, hostname, partner, my_ip, other_ip, port, socket, my_pub_key,
                 my_priv_key, connections, state=ConnectionState.CLIENT_HELLO):
        self.hostname = hostname
        self.ip = my_ip
        self.partner = partner
        self.partner_ip = other_ip
        self.s = socket
        self.state = state
        self.q = Queue()
        self.pub_key = my_pub_key
        self.priv_key = my_priv_key
        self.partner_key = None
        self.symmetric_key = None
        self.sent_nonce = None
        self.partner_nonce = None
        self.rng = os.urandom
        self.thread = None
        self.is_open = True
        self.node_connections = connections
        self.last_ts_received = 0

        # Diffie-Hellman fields
        self.temp_priv_key = None
        self.temp_pub_key = None
        self.dh_parameters = None
        self.salt = None
        # self.timestamp = int(time.time())

    def initiate_connection(self):
        def go():
            self.send_pub_key()
            self.recv_pub_key()
            self.send_dh_contribution()
            self.recv_dh_contribution()
            print("Handshake completed with Host {}".format(self.partner))
            self.processing_loop()

        self.thread = threading.Thread(target=go)
        self.thread.start()

    def receive_connection(self):
        def go():
            self.recv_pub_key()
            self.send_pub_key()
            self.recv_dh_contribution()
            self.send_dh_contribution()
            print("Handshake completed with Host {}".format(self.partner))
            self.processing_loop()

        self.thread = threading.Thread(target=go)
        self.thread.start()

    def close_connection(self):
        self.is_open = False
        self.state = ConnectionState.CLOSED
        self.node_connections.pop(self.partner_ip)
        print("Closed connection with {}".format(self.partner))

    def processing_loop(self):
        while self.is_open:
            ready_socks, _, _ = select.select([self.s], [], [], 0)
            if len(ready_socks) > 0:
                data = self.s.recv(65535)
                if data == b'':
                    self.close_connection()
                elif self.is_active():
                    self.recv_message(data)

            if self.is_open:
                while not self.q.empty() and self.is_active():
                    msg = self.q.get()
                    self.send_message(msg)
        self.s.shutdown(socket.SHUT_RDWR)
        self.s.close()

    def advance_state(self):
        self.state = {
            ConnectionState.CLIENT_HELLO: ConnectionState.CLIENT_CIPHER_SENT,
            ConnectionState.SERVER_HELLO: ConnectionState.SERVER_CIPHER_SENT,
            ConnectionState.CLIENT_CIPHER_SENT: ConnectionState.ACTIVE,
            ConnectionState.SERVER_CIPHER_SENT: ConnectionState.ACTIVE,
            # ConnectionState.ACTIVE: ConnectionState.ACTIVE,
        }[self.state]

    def is_active(self):
        return self.state == ConnectionState.ACTIVE

    def is_closed(self):
        return self.state == ConnectionState.CLOSED

    def add_to_queue(self, msg):
        self.q.put(msg)

    def is_ts_valid(self, ts):
        age = int(time.time()) - ts
        return self.last_ts_received < ts and 0 <= age <= TIMEOUT

    def recv_message(self, msg):
        try:
            message = bson.loads(msg)
            decrypted_bytes = self.symmetric_key.decrypt(
                message['iv'], message['encrypted_bytes'], None)
            sig_payload = bson.loads(decrypted_bytes)

            self.handle_message(sig_payload['signature'], sig_payload['meta_payload'])

        except Exception as e:
            print("Malformed message")
            print(e)
            return

    def handle_message(self, sig: bytes, meta_p: bytes):
        try:
            self.partner_key.verify(
                sig,
                meta_p,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            meta_payload = bson.loads(meta_p)

            if not self.is_ts_valid(meta_payload['timestamp']):
                return

            self.last_ts_received = meta_payload['timestamp']

            print("Message from host {}: {}".format(
                self.partner, meta_payload['payload']))
        except InvalidSignature:
            print("Invalid Signature")
            return
        except Exception as e:
            print(e)
            return

    def build_message(self, payload):
        meta_payload = dict()
        meta_payload['type'] = "data"
        meta_payload['payload'] = payload
        meta_payload['timestamp'] = int(time.time())
        return meta_payload

    def send_message(self, msg):

        build_payload = self.build_message(msg)

        build_bytes = bson.dumps(build_payload)
        sig = self.priv_key.sign(
            build_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        sig_payload = dict()
        sig_payload['meta_payload'] = build_bytes
        sig_payload['signature'] = sig

        message = dict()

        iv = self.rng(16)
        message['iv'] = iv
        enc_payload = bson.dumps(sig_payload)

        message['encrypted_bytes'] = self.symmetric_key.encrypt(
            iv, enc_payload, None)
        message_bytes = bson.dumps(message)

        self.s.sendall(message_bytes)

    def send_pub_key(self):
        message = dict()
        message['type'] = "public_key"
        nonce = self.rng(8)
        message['new_nonce'] = nonce
        self.sent_nonce = nonce
        if self.partner_nonce is not None:
            message['prev_nonce'] = self.partner_nonce
        message['timestamp'] = int(time.time())
        message['public_key'] = self.pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        message_bytes = bson.dumps(message)

        self.s.sendall(message_bytes)
        self.advance_state()

    def recv_pub_key(self):
        while True:
            try:
                message_bytes = self.s.recv(65535)
                message = bson.loads(message_bytes)
                if message['type'] != "public_key" and self.sent_nonce is not None \
                        and message['prev_nonce'] != self.sent_nonce:
                    continue

                if not self.is_ts_valid(message['timestamp']):
                    continue

                self.partner_nonce = message['new_nonce']
                self.partner_key = serialization.load_pem_public_key(
                    message['public_key'], backend=default_backend())
                # self.advance_state()
                return
            except Exception as e:
                print(e)
                self.partner_nonce = None
                self.partner = None
                continue

    def send_dh_contribution(self):
        """
        Send my Diffie-Hellman contribution to my partner.

        Two scenarios:
        (1) I initiated a connection: I am generating DH parameters and sending my DH
        contribution
        (2) I received a connection: I received DH parameters and I'm sending my DH
        contribution

        Payload includes my temporary DH "public key" (basically my DH contribution) and
        DH parameters if initiating connection. Payload is added to the meta_payload
        bson, which contains metadata about the payload. The meta_payload is dumped,
        encoded, signed and added to the message bson. The generated signature is added
        to the message bson. The message is dumped and encoded then sent to the partner.

        """

        payload = dict()
        if self.temp_priv_key is None and self.temp_pub_key is None \
                and self.dh_parameters is None and self.salt is None:
            # NOTE: the below command took a while in my Python console... will issue persist in actual implementation?
            self.dh_parameters = dh.generate_parameters(
                generator=2,
                key_size=2048,
                backend=default_backend()
            )
            self.temp_priv_key = self.dh_parameters.generate_private_key()
            self.temp_pub_key = self.temp_priv_key.public_key()
            self.salt = self.rng(16)

            payload['salt'] = self.salt

            payload['dh_parameters'] = self.dh_parameters.parameter_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.ParameterFormat.PKCS3
            )
        payload['dh_contribution'] = self.temp_pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        meta_payload = dict()
        meta_payload['type'] = "dh_contribution"
        nonce = self.rng(8)
        meta_payload['new_nonce'] = nonce
        self.sent_nonce = nonce
        meta_payload['prev_nonce'] = self.partner_nonce
        meta_payload['payload'] = payload
        meta_payload['timestamp'] = int(time.time())

        message = dict()
        message["meta_payload"] = bson.dumps(meta_payload)
        sig = self.priv_key.sign(
            message["meta_payload"],
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        message["signature"] = sig

        message_bytes = bson.dumps(message)
        self.s.sendall(message_bytes)
        self.advance_state()

    def recv_dh_contribution(self):
        """
        Receive my partner's Diffie-Hellman contribution.

        Loads and decodes received message, verifies signature (throws InvalidSignature
        exception if invalid), loads and decodes received meta_payload, checks prev_nonce
        and payload type, sets partner_nonce to new_nonce, handles partner's DH
        contribution.

        Continues to wait for partner's DH contribution until a valid DH contribution is
        received. Ignores all other messages.

        """
        while True:
            try:
                message_bytes = self.s.recv(65535)
                message = bson.loads(message_bytes)
                self.partner_key.verify(
                    message['signature'],
                    message['meta_payload'],
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

                meta_payload = bson.loads(message['meta_payload'])
                if meta_payload['prev_nonce'] != self.sent_nonce \
                        or meta_payload['type'] != "dh_contribution":
                    print("continuing for invalid nonce or type")
                    continue
                else:
                    # TODO awkward if-else-if-not logic, fix later?
                    if not self.handle_dh_contribution(meta_payload):
                        print("continuing because of handle function")
                        continue
                    self.partner_nonce = meta_payload['new_nonce']
                    return

            except InvalidSignature:
                print("Invalid Signature")
                continue
            except Exception as e:
                print(e)
                continue

    def handle_dh_contribution(self, meta_payload):
        """
        Attempt to create symmetric key with partner's DH contribution. Message validity
        is checked in calling function (recv_dh_contribution)

        Two scenarios:
        (1) I initiated a connection: My DH fields should NOT be empty since I generated
         DH parameters. Create symmetric key with received partner's DH contribution

        (2) I received a connection: My DH fields should be empty. Generate my DH
         temp_priv_key and temp_pub_key with the received DH parameters. Create symmetric
         key with received partner's DH contribution.

        :param meta_payload: bson (decrypted and decoded)
        :return True if successful symmetric key was generated, False otherwise

        """

        try:
            partner_temp_pub = serialization.load_pem_public_key(
                    meta_payload['payload']['dh_contribution'],
                    backend=default_backend()
            )
            if self.temp_priv_key is None and self.temp_pub_key is None \
                    and self.dh_parameters is None and self.salt is None:
                self.dh_parameters = serialization.load_pem_parameters(
                    meta_payload['payload']['dh_parameters'],
                    backend=default_backend()
                )
                self.temp_priv_key = self.dh_parameters.generate_private_key()
                self.temp_pub_key = self.temp_priv_key.public_key()

                self.salt = meta_payload['payload']['salt']

            self.symmetric_key = AESGCM(
                HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=self.salt,
                    info=None,
                    backend=default_backend()
                ).derive(self.temp_priv_key.exchange(partner_temp_pub))
            )
            return True

        except Exception as e:
            print(e)
            return False


class Node:
    def __init__(self, hostname, my_ip, port=5555, hosts=dict()):
        self.priv_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.pub_key = self.priv_key.public_key()
        self.hostname = hostname
        self.ip = my_ip
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((my_ip, port))
        self.sock.listen(5)
        self.host_to_ip = hosts
        self.ip_to_host = {v: k for k, v in hosts.items()}
        self.connections = dict()
        self.is_running = True

    def create_connection(self, partner, partner_ip, sock):
        return Connection(self.hostname, partner, self.ip, partner_ip,
                          self.port, sock, self.pub_key, self.priv_key, self.connections)

    def go(self):
        while self.is_running:
            ready_socks, _, _ = select.select([self.sock], [], [], 0)
            if len(ready_socks) > 0:
                partner_sock, (partner_ip, _) = self.sock.accept()
                partner = self.ip_to_host[partner_ip]
                print("received connection request from %s" % partner)

                conn = self.create_connection(
                    partner, partner_ip, partner_sock)
                self.connections[partner_ip] = conn
                conn.receive_connection()
        self.sock.close()

    def handle_input(self):
        for line in sys.stdin:
            words = line.split()
            command = words[0]
            if command == "connect":
                partner = words[1]
                partner_ip = self.host_to_ip[partner]
                if partner_ip in self.connections:
                    continue
                partner_sock = socket.create_connection(
                    (partner_ip, self.port))
                conn = self.create_connection(
                    partner, partner_ip, partner_sock)
                self.connections[partner_ip] = conn
                conn.initiate_connection()
            elif command == "send":
                partner = words[1]
                partner_ip = self.host_to_ip[partner]
                if partner_ip not in self.connections:
                    print("connection not currently active with Node {}".format(partner))
                else:
                    msg = ' '.join(words[2:])
                    self.connections[partner_ip].add_to_queue(msg)
            elif command == "close":
                partner = words[1]
                partner_ip = self.host_to_ip[partner]
                if partner_ip not in self.connections:
                    print("connection not currently active with Node {}".format(partner))
                else:
                    self.connections[partner_ip].close_connection()
            elif command == "exit":
                return
            else:
                print("Invalid command: {}".format(command))

    def shutdown(self):
        self.is_running = False
        for _, c in dict(self.connections).items():
            c.close_connection()


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: python3 protocol.py config_file")
    with open(sys.argv[1], 'r') as f:
        config = yaml.safe_load(f)
    hostname = config['hostname']
    ip = config['ip']
    port = config['port']
    hosts = {x['hostname']: x['ip'] for x in config['peers']}
    print(hosts)
    n = Node(hostname, ip, port=port, hosts=hosts)
    listener = threading.Thread(target=lambda: n.go())
    listener.start()
    n.handle_input()
    n.shutdown()


if __name__ == "__main__":
    main()


'''

connect [hostname]
send [hostname] [data]




bytes = recv()
if message_type is client_hello:
    process_hello()


'''
