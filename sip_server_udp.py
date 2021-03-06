'''SIP Server with iOS Push Notification Capabilities
Copyright (C) 2017 Francisco Burgos Collazo  

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

"Code yourself out life is short..." Me :)  and please, share and enjoy... 
'''

import socketserver
import re
import socket
import threading
import sys
import traceback
import time
import logging
from pushjack import APNSClient
import sqlite3
import os
from sip_user import SipUser
import ipgetter


HOST, PORT = (os.environ.get('SIP_SERVER_HOST') or '0.0.0.0'), (os.environ.get('SIP_SERVER_PORT') or 7654)
rx_register = re.compile("^REGISTER")
rx_invite = re.compile("^INVITE")
rx_ack = re.compile("^ACK")
rx_prack = re.compile("^PRACK")
rx_cancel = re.compile("^CANCEL")
rx_bye = re.compile("^BYE")
rx_options = re.compile("^OPTIONS")
rx_subscribe = re.compile("^SUBSCRIBE")
rx_publish = re.compile("^PUBLISH")
rx_notify = re.compile("^NOTIFY")
rx_info = re.compile("^INFO")
rx_message = re.compile("^MESSAGE")
rx_refer = re.compile("^REFER")
rx_update = re.compile("^UPDATE")
rx_from = re.compile("^From:")
rx_cfrom = re.compile("^f:")
rx_to = re.compile("^To:")
rx_cto = re.compile("^t:")
rx_tag = re.compile(";tag")
rx_contact = re.compile("^Contact:")
rx_cContact = re.compile("^m:")
rx_uri = re.compile("sip:([^@]*)@([^;>$]*)")
rx_addr = re.compile("sip:([^ ;>$]*)")
rx_code = re.compile("^SIP/2.0 ([^ ]*)")
rx_rr = re.compile("^Record-Route:")
rx_request_uri = re.compile("^([^ ]*) sip:([^ ]*) SIP/2.0")
rx_route = re.compile("^Route:")
rx_contentLength = re.compile("^Content-Length:")
rx_user_agent = re.compile("User-Agent:([^@]*)")
rx_token = re.compile("pn-token=([^@]*)")
rx_cContentLength = re.compile("^l:")
rx_via = re.compile("^Via:")
rx_cVia = re.compile("^v:")
rx_branch = re.compile(";branch=([^;]*)")
rx_rport = re.compile(";rport$|;rport;")
rx_contact_expires = re.compile("expires=([^;$]*)")
rx_expires = re.compile("^Expires: (.*)$")

# global dictionary
development = True
public_ip = ipgetter.myip()
apns = APNSClient(certificate=os.environ.get('PATH_TO_PN_CERT'),
                  default_error_timeout=10,
                  default_expiration_offset=2592000,
                  default_batch_size=100)
recordRoute = ""
topVia = ""
registrar = {}
push_notification = {}
db = sqlite3.connect("sip_registrar")
cursor = db.cursor()

def hexdump(chars, sep, width):
    while chars:
        line = chars[:width]
        chars = chars[width:]
        line = line.ljust(width, '\000')
        logging.info("%s%s%s" % (sep.join("%02x" % ord(c) for c in line), sep, quotechars(line)))

def quotechars(chars):
    return ''.join(['.', c][c.isalnum()] for c in chars)

def showtime():
    logging.info(time.strftime("(%H:%M:%S)", time.localtime()))

def sendPushNotificationFR():

    for user in cursor.execute("SELECT * FROM registrar"):
        token_hex = str(user[3])
        if token_hex:
            try:
                res = apns.send(token_hex,
                                  'Register',
                                  badge=1,
                                  sound='Default',
                                  content_available=True,
                                  title='SIP Server Notification')
            except res.errors as e:
                # logging.warning("Error happened sending request to apns service: %s -------- %s" %(e.__doc__, e.message))
                logging.error(traceback.format_exc())
                server.shutdown()
                server.server_close()
                sys.exit(1)

    t = threading.Timer(30.0, sendPushNotificationFR)
    return t.start()

timer = threading.Timer(30.0, sendPushNotificationFR)

class UDPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        data = str(self.request[0], 'utf-8')
        self.data = data.split('\r\n')
        self.expires =True
        self.socket = self.request[1]
        request_uri = self.data[0]
        self.blacklisted_user_agents = ['sipcli', 'sipvicious', 'sip-scan', 'sipsak', 'sundayddr',
                                        'friendly-scanner', 'iWar', 'CSipSimple', 'SIVuS', 'Gulp',
                                        'sipv', 'smap', 'friendly-request', 'VaxIPUserAgent', 'VaxSIPUserAgent',
                                        'siparmyknife', 'Test Agent']
        self.sip_user = SipUser()
        self.db_connection = sqlite3.connect('sip_registrar.db')
        self.db_cursor = self.db_connection.cursor()

        if rx_request_uri.search(request_uri) or rx_code.search(request_uri):
            showtime()
            if self.security_check():
                self.process_request()
            else:
                logging.warning("server security check not passed from client: %s:%s" % (self.client_address[0], str(self.client_address[1])))
        else:
            if len(data) > 4:
                showtime()
                logging.warning("---\n>> server received [%d]:" % len(data))
                hexdump(data, ' ', 16)
                logging.warning("---")

    def send_push_notification(self, token, caller):
        try:
            res = apns.send(token,
                            'You have an incoming call from %s' % caller,
                            badge=1,
                            sound='Default',
                            content_available=True,
                            title='SIP Server Notification')
        except Exception as e:
            # logging.warning("Error happened sending request to apns service: %s -------- %s" %(e.__doc__, e.message))
            logging.error(traceback.format_exc())
            server.shutdown()
            server.server_close()
            sys.exit(1)

    def remove_route_header(self):
        # delete Route
        data = []
        for line in self.data:
            if not rx_route.search(line):
                data.append(line)
        return data

    def add_top_via(self):
        branch= ""
        data = []
        for line in self.data:
            if rx_via.search(line) or rx_cVia.search(line):
                md = rx_branch.search(line)
                if md:
                    branch=md.group(1)
                    via = "%s;branch=%sm" % (topVia, branch)
                    data.append(via)
                # rport processing
                if rx_rport.search(line):
                    text = "received=%s;rport=%d" % self.client_address
                    via = line.replace("rport", text)
                else:
                    text = "received=%s" % self.client_address[0]
                    via = "%s;%s" % (line, text)
                data.append(via)
            else:
                data.append(line)
        return data

    def remove_top_via(self):
        data = []
        for line in self.data:
            if rx_via.search(line) or rx_cVia.search(line):
                if not line.startswith(topVia):
                    data.append(line)
            else:
                data.append(line)
        return data

    def security_check(self):
        for index, line in enumerate(self.data):
            if rx_user_agent.search(line):
                ua = rx_user_agent.search(line).group(1)
                if ua in self.blacklisted_user_agents:
                    self.send_response("495 Further Requests Will Be Tracerouted")
                    logging.warning("Malicious user agent %s found server response sent" % ua)
                    valid = False
                    break
                else:
                    valid = True
                    break
            elif index == len(self.data)-1:
                valid = False
        if valid:
            return True
        else:
            return False

    def check_validity(self, uri):
        timestamp = self.db_cursor.execute("SELECT validity FROM registrar WHERE uri=?", (uri,)).fetchone()
        if timestamp:
            now = int(time.time())
            if timestamp[0] > now:
                return True
            else:
                self.db_cursor.execute("DELETE FROM registrar WHERE uri=?", (uri,))
                logging.info("registration for %s has expired" % uri)
                return False

    def get_socket_info(self, uri):
        user = self.db_cursor.execute("SELECT * FROM registrar WHERE uri=?", (uri,)).fetchone()
        if user:
            return user[1], user[2], user[3]
        else:
            self.send_response("404 Not Found")

    def get_destination(self):
        destination = ""
        for line in self.data:
            if rx_to.search(line) or rx_cto.search(line):
                md = rx_uri.search(line)
                if md:
                    destination = "%s@%s" %(md.group(1), md.group(2))
                break
        return destination

    def get_origin(self):
        origin = ""
        for line in self.data:
            if rx_from.search(line) or rx_cfrom.search(line):
                md = rx_uri.search(line)
                if md:
                    origin = "%s@%s" %(md.group(1),md.group(2))
                break
        return origin

    def send_response(self, code):
        request_uri = "SIP/2.0 " + code
        self.data[0] = request_uri
        index = 0
        data = []
        for line in self.data:
            data.append(line)
            if rx_to.search(line) or rx_cto.search(line):
                if not rx_tag.search(line):
                    data[index] = "%s%s" % (line,";tag=123456")
            if rx_via.search(line) or rx_cVia.search(line):
                # rport processing
                if rx_rport.search(line):
                    text = "received=%s;rport=%d" % self.client_address
                    data[index] = line.replace("rport",text)
                else:
                    text = "received=%s" % self.client_address[0]
                    data[index] = "%s;%s" % (line,text)
            if rx_contentLength.search(line):
                data[index]="Content-Length: 0"
            if rx_cContentLength.search(line):
                data[index]="l: 0"
            index += 1
            if line == "":
                if not self.expires:
                    data[index-1] = "Expires: 3600"
                break
        data.append("")
        text = '\r\n'.join(data)
        self.socket.sendto(bytes(text, 'utf-8'), self.client_address)

    def process_register(self):
        fromm = ""
        contact = ""
        contact_expires = ""
        header_expires = ""
        expires = 0
        validity = 0
        authorization = ""
        index = 0
        auth_index = 0
        data = []
        size = len(self.data)
        for line in self.data:
            if rx_to.search(line) or rx_cto.search(line):
                md = rx_uri.search(line)
                if md:
                    fromm = "%s@%s" % (md.group(1), md.group(2))
            if rx_contact.search(line) or rx_cContact.search(line):
                md = rx_uri.search(line)
                if md:
                    contact = md.group(2)
                    if rx_token.search(line):
                        token = rx_token.search(line).group(1)
                    else:
                        token = ''
                        # logging.warning("Someone tried registering without push notification token from %s:%s" % (self.client_address[0], self.client_address[1]))
                else:
                    md = rx_addr.search(line)
                    if md:
                        contact = md.group(1)
                md = rx_contact_expires.search(line)
                if md:
                    contact_expires = md.group(1)
            md = rx_expires.search(line)
            if md:
                header_expires = md.group(1)
        if len(contact_expires) > 0:
            expires = int(contact_expires)
        elif len(header_expires) > 0:
            expires = int(header_expires)
        else:
            self.expires = False
            token = ''

        already_registered = False
        self.db_cursor.execute('''CREATE TABLE IF NOT EXISTS registrar (uri text, host text, port integer, token text, validity int)''')
        for contact in self.db_cursor.execute('''SELECT * FROM registrar''').fetchall():
            if fromm == contact[0] and self.client_address[0] == contact[1] and self.client_address[1] == contact[2]:
                already_registered = True
                break

        if not already_registered and expires > 0:
            now = time.time()
            validity = now + expires
            data = (fromm, self.client_address[0], self.client_address[1], token, validity)
            self.sip_user.set_user_info(data)
            self.db_cursor.execute("INSERT INTO registrar VALUES (?, ?, ?, ?, ?)", self.sip_user.get_user_info())
        elif already_registered and expires == 0 and self.expires:
            self.db_cursor.execute("DELETE FROM registrar WHERE uri=?", (fromm,))
            self.db_connection.commit()
            self.send_response("200 OK")
            return
        elif not self.expires and not already_registered:
            now = time.time()
            validity = now + 3600
            data = (fromm, self.client_address[0], self.client_address[1], token, validity)
            self.sip_user.set_user_info(data)
            self.db_cursor.execute("INSERT INTO registrar VALUES (?, ?, ?, ?, ?)", self.sip_user.get_user_info())
            self.db_connection.commit()
            self.send_response("200 OK")
            return

        request = '\r\n'.join(self.data)
        showtime()
        logging.info("<<< %s" % self.data[0])
        logging.info("---\n<< USER REGISTERED [%d]:\n%s\n---" % (len(request), request))
        self.db_connection.commit()
        self.send_response("200 OK")

    def process_invite(self):
        origin = self.get_origin()
        destination = self.get_destination()
        if len(origin) == 0 or len(destination) == 0:
            self.send_response("400 Bad Request")
            return
        if self.db_cursor.execute("SELECT * FROM registrar WHERE uri=?", (destination,)).fetchone():
            client_ip, client_port, token = self.get_socket_info(destination)
            client_address = (client_ip, client_port)
            if token is not '':
                self.send_push_notification(token, origin)
                showtime()
                logging.info("Invite Push Notification sent to pn-token: %s" % token)
            data = self.remove_route_header()
            data.insert(1, recordRoute)
            request = '\r\n'.join(data)
            self.send_response("100 Trying")
            self.socket.sendto(bytes(request, 'utf-8'), client_address)
            showtime()
            logging.info(">>> %s" % self.data[0])
            logging.info("---\n>>> client sent [%d]:\n%s\n---" % (len(request), request))

        else:
            self.send_response("404 Not Found")
            request = '\r\n'.join(self.data)
            showtime()
            logging.info("<<< %s" % self.data[0])
            logging.info("---\n<< client failed with 404 [%d]:\n%s\n---" % (len(request), request))

    def process_ack(self):
        destination = self.get_destination()
        if len(destination) > 0:
            if self.db_cursor.execute("SELECT uri FROM registrar WHERE uri=?", (destination,)).fetchone():
                client_ip, client_port, token = self.get_socket_info(destination)
                client_address = (client_ip, client_port)
                data = self.remove_route_header()
                data.insert(1, recordRoute)
                request = '\r\n'.join(data)
                self.socket.sendto(bytes(request, 'utf-8'), client_address)
                showtime()
                logging.info(">>> %s" % self.data[0])
                logging.info("---\n>> client sent [%d]:\n%s\n---" % (len(request), request))
            else:
                self.send_response("404 Not Found")
                request = '\r\n'.join(self.data)
                showtime()
                logging.info("<<< %s" % self.data[0])
                logging.info("---\n<< client failed with 404 [%d]:\n%s\n---" % (len(request), request))


    def process_non_invite(self):
        origin = self.get_origin()
        destination = self.get_destination()
        if len(origin) == 0 or len(destination) == 0:
            self.send_response("400 Bad Request")
            logging.warning("---------------------------------------------------------")
            logging.warning('''Server Sent Error to client because destination or origin in 
                            request is ambiguous: origin-%s''' % origin)
            logging.warning('''Server Sent Error to client because destination or origin in 
                            request is ambiguous: destination-%s ''' % destination)
            logging.warning("---------------------------------------------------------")
            return
        if len(destination) > 0:
            if self.db_cursor.execute("SELECT uri FROM registrar WHERE uri=?", (destination,)).fetchone():
                client_ip, client_port, token = self.get_socket_info(destination)
                client_address = (client_ip, client_port)
                data = self.remove_route_header()
                data.insert(1, recordRoute)
                request = '\r\n'.join(data)
                self.socket.sendto(bytes(request, 'utf-8'), client_address)
                showtime()
                logging.info(">>> %s" % self.data[0])
                logging.info("---\n>> client sent [%d]:\n%s\n---" % (len(request), request))
            else:
                self.send_response("404 Not Found")
                request = '\r\n'.join(self.data)
                showtime()
                logging.info("<<< %s" % self.data[0])
                logging.info("---\n<< client failed with 404 [%d]:\n%s\n---" % (len(request), request))

    def process_code(self):
        origin = self.get_origin()
        if len(origin) > 0:
            logging.debug("origin %s" % origin)
            if self.db_cursor.execute("SELECT * FROM registrar WHERE uri=?", (origin,)).fetchone():
                client_ip, client_port, token = self.get_socket_info(origin)
                self.data = self.remove_route_header()
                data = self.remove_top_via()
                text = '\r\n'.join(data)
                claddr = (client_ip, client_port)
                self.socket.sendto(bytes(text, 'utf-8'), claddr)
                showtime()
                logging.info("<<< %s" % data[0])
                logging.info("---\n<< server send [%d]:\n%s\n---" % (len(text), text))

    def process_request(self):
        if len(self.data) > 0:
            request_uri = self.data[0]
            logging.info("Received: " + request_uri + " From: " + self.client_address[0] + ":" + str(self.client_address[1]))
            print("Received: " + request_uri + " From: " + self.client_address[0] + ":" + str(self.client_address[1]))
            if rx_register.search(request_uri):
                self.process_register()
            elif rx_invite.search(request_uri):
                self.process_invite()
            elif rx_ack.search(request_uri):
                self.process_ack()
            elif rx_bye.search(request_uri):
                self.process_bye()
            elif rx_cancel.search(request_uri):
                self.process_non_invite()
            elif rx_options.search(request_uri):
                self.process_non_invite()
            elif rx_info.search(request_uri):
                self.process_non_invite()
            elif rx_message.search(request_uri):
                self.process_non_invite()
            elif rx_refer.search(request_uri):
                self.process_non_invite()
            elif rx_prack.search(request_uri):
                self.process_non_invite()
            elif rx_update.search(request_uri):
                self.process_non_invite()
            elif rx_subscribe.search(request_uri):
                self.process_non_invite()
            elif rx_publish.search(request_uri):
                self.process_non_invite()
            elif rx_notify.search(request_uri):
                self.process_non_invite()
            elif rx_code.search(request_uri):
                self.process_code()
            else:
                logging.warning("request_uri %s" % request_uri)


if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s', filename='/var/log/SIP_Server.log', level=logging.INFO, datefmt='%H:%M:%S')
    logging.info(time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime()))
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    recordRoute = "Record-Route: <sip:%s:%d;lr>" % (public_ip, PORT)
    topVia = "Via: SIP/2.0/UDP %s:%d" % (public_ip, PORT)
    server = socketserver.UDPServer((HOST, PORT), UDPHandler)
    logging.info("Server is running on public ip -> " + public_ip + ":" + str(PORT))
    print("Server is running on public ip -> " + public_ip + ":" + str(PORT))
    logging.info("Server is running on private ip -> " + ip_address + ":" + str(PORT))
    print("Server is running on private ip -> " + ip_address + ":" + str(PORT))
    try:
        # timer.start()
        server.serve_forever()
    except Exception as e:
        logging.error("system exit with error see logs for details")
        sys.exit(1)
