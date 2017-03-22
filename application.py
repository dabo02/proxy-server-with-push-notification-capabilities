#    Copyright 2014 Philippe THIRION
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import SocketServer
import re
import string
import socket
import threading
import sys
import time
import logging
from apns import APNs, Frame, Payload
import pyrebase

HOST, PORT = '0.0.0.0', 5060
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
#rx_addrport = re.compile("([^:]*):(.*)")
rx_code = re.compile("^SIP/2.0 ([^ ]*)")
# rx_invalid = re.compile("^192\.168")
# rx_invalid2 = re.compile("^10\.")
#rx_cseq = re.compile("^CSeq:")
#rx_callid = re.compile("Call-ID: (.*)$")
#rx_rr = re.compile("^Record-Route:")
rx_request_uri = re.compile("^([^ ]*) sip:([^ ]*) SIP/2.0")
rx_route = re.compile("^Route:")
rx_contentLength = re.compile("^Content-Length:")
rx_token = re.compile("pn\-token=([^@]*)")
rx_cContentLength = re.compile("^l:")
rx_via = re.compile("^Via:")
rx_cVia = re.compile("^v:")
rx_branch = re.compile(";branch=([^;]*)")
rx_rport = re.compile(";rport$|;rport;")
rx_contact_expires = re.compile("expires=([^;$]*)")
rx_expires = re.compile("^Expires: (.*)$")

# global dictionary
development = False
if development:
    public_ip = "207.204.176.127"
    email = 'fburgos@optivon.net'
    password = 'optivon_787'
    apns = APNs(use_sandbox=True, cert_file='/home/dabo02/Desktop/Projects/Work/VoipPushProto/MercurioVoipPush.pem')
    config = {'apiKey': "AIzaSyAlTNQ0rX_z49-EL71e8le0vPew16g8WDg",
              'authDomain': "mercurio-development.firebaseapp.com",
              'databaseURL': "https://mercurio-development.firebaseio.com",
              'storageBucket': "mercurio-development.appspot.com",
              'messagingSenderId': "203647142462"}

else:
    public_ip = '54.165.3.139'
    email = 'fburgos@optivon.net'
    password = 'optivon_787'
    apns = APNs(use_sandbox=True, cert_file='/home/admin/VoipPush/MercurioVoipPush.pem')
    # config = {'apiKey': "AIzaSyBYty0ff3hxlmwmBjy7paWCEalIrJxDpZ8",
    #     'authDomain': "mercurio-39a44.firebaseapp.com",
    #     'databaseURL': "https://mercurio-39a44.firebaseio.com",
    #     'storageBucket': "mercurio-39a44.appspot.com"
    #     }
    config = {'apiKey': "AIzaSyAlTNQ0rX_z49-EL71e8le0vPew16g8WDg",
              'authDomain': "mercurio-development.firebaseapp.com",
              'databaseURL': "https://mercurio-development.firebaseio.com",
              'storageBucket': "mercurio-development.appspot.com",
              'messagingSenderId': "203647142462"}

reg_addr = ('63.131.240.90', 5060)
recordRoute = ""
topVia = ""
registrar = {}
push_notification = {}

firebase = pyrebase.initialize_app(config)
auth = firebase.auth()
user = auth.sign_in_with_email_and_password(email, password)
db = firebase.database()
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
    registrees = db.child('voip-registrar').get()
    if registrees.val():
        for reg in registrees.each():
            token_hex = str(reg.val()['pn-token'])
            if token_hex != 'Empty' and token_hex:
                payload = Payload(alert='Register', sound='Default', badge=1)
                apns.gateway_server.send_notification(token_hex, payload)
    t = threading.Timer(30.0, sendPushNotificationFR)
    t.start()

timer = threading.Timer(30.0, sendPushNotificationFR)

class UDPHandler(SocketServer.BaseRequestHandler):

    def debugRegister(self):
        regs = db.child('voip-registrar').get()


    def sendPushNotification(self, token, caller):
        payload = Payload(alert=('You have an incoming call from %s' % caller), sound='Default', badge=1)
        apns.gateway_server.send_notification(token, payload)

    def changeRequestUri(self):
        # change request uri
        md = rx_request_uri.search(self.data[0])
        if md:
            method = md.group(1)
            uri = md.group(2)
            if registrar.has_key(uri):
                uri = "sip:%s" % registrar[uri][0]
                self.data[0] = "%s %s SIP/2.0" % (method, uri)

    def removeRouteHeader(self):
        # delete Route
        data = []
        for line in self.data:
            if not rx_route.search(line):
                data.append(line)
        return data

    def addTopVia(self):
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

    def removeTopVia(self):
        data = []
        for line in self.data:
            if rx_via.search(line) or rx_cVia.search(line):
                if not line.startswith(topVia):
                    data.append(line)
            else:
                data.append(line)
        return data

    def checkValidity(self, uri):
        registress = db.child('voip-registrar').get()
        for reg in registress.each():
            if reg.val()['contact'] == uri:
                contact = reg
        now = int(time.time())
        if contact.val()['validity'] > now:
            return True
        else:
            db.child(contact.key()).remove()
            logging.info("registration for %s has expired" % uri)
            return False

    def getSocketInfo(self, uri):
        all_registrees = db.child('voip-registrar').get()
        if all_registrees.val():
            for reg in all_registrees.each():
                if reg.val()['contact'] == uri:
                        return (reg.val()['client_ip'], reg.val()['client_port'], reg.val()['pn-token'])

    def getDestination(self):
        destination = ""
        for line in self.data:
            if rx_to.search(line) or rx_cto.search(line):
                md = rx_uri.search(line)
                if md:
                    destination = "%s@%s" %(md.group(1), md.group(2))
                break
        return destination

    def getOrigin(self):
        origin = ""
        for line in self.data:
            if rx_from.search(line) or rx_cfrom.search(line):
                md = rx_uri.search(line)
                if md:
                    origin = "%s@%s" %(md.group(1),md.group(2))
                break
        return origin

    def sendResponse(self, code):
        request_uri = "SIP/2.0 " + code
        self.data[0]= request_uri
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
                break
        data.append("")
        text = string.join(data, '\r\n')
        self.socket.sendto(text, self.client_address)

    def processRegister(self):
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
                        self.sendResponse("407 Proxy Authentication Required")
                        return
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

        # if rx_invalid.search(contact) or rx_invalid2.search(contact):
        # 	if registrar.has_key(fromm):
        # 		del registrar[fromm]
        # 	self.sendResponse("488 Not Acceptable Here")
        # 	return
        if len(contact_expires) > 0:
            expires = int(contact_expires)
        elif len(header_expires) > 0:
            expires = int(header_expires)

        all_registrees = db.child('voip-registrar').get()
        if all_registrees.val():
            for reg in all_registrees.each():
                if reg.val()['contact'] == fromm and reg.val()['client_ip'] == self.client_address[0] and reg.val()['client_port'] == self.client_address[1]:
                    already_registered = True
                    con = reg.key()
                else:
                    already_registered = False
        else:
            already_registered = False
        # if already_registered:
        #     self.checkValidity(fromm)

        if (not already_registered and expires > 0) or not already_registered:
            now = int(time.time())
            validity = now + expires
            data = {'contact': fromm, 'client_ip': self.client_address[0], 'client_port': self.client_address[1], 'validity': validity, 'pn-token': token}
            db.child('voip-registrar').push(data)
        elif already_registered and expires == 0:
            db.child('voip-registrar').child(con).remove()

        self.data.insert(1, recordRoute)
        request = string.join(self.data, "\r\n")
        self.socket.sendto(request, reg_addr)
        showtime()
        logging.info("<<< %s" % self.data[0])
        logging.info("---\n<< Registration sent to registrar [%d]:\n%s\n---" % (len(request), request))




    def processInvite(self):
        origin = self.getOrigin()
        if len(origin) == 0:
            self.sendResponse("400 Bad Request")
            return
        destination = self.getDestination()
        if len(destination) > 0:
            if self.client_address == reg_addr:
                client_ip, client_port, token = self.getSocketInfo(destination)
                client_address = (client_ip, client_port)
                if token is not None:
                    caller = self.getOrigin()
                    self.sendPushNotification(token, caller)
                    showtime()
                    logging.info("Invite Push Notification sent to pn-token: %s" % token)
                request = string.join(self.data, '\r\n')
                self.socket.sendto(request, client_address)
                showtime()
                logging.info("<<< %s" % self.data[0])
                logging.info("---\n<< server sent [%d]:\n%s\n---" % (len(request), request))

            else:
                data = self.removeRouteHeader()
                #insert Record-Route
                data.insert(1, recordRoute)
                request = string.join(data, '\r\n')
                self.socket.sendto(request, reg_addr)
                showtime()
                logging.info(">>> %s" % self.data[0])
                logging.info("---\n>> client sent [%d]:\n%s\n---" % (len(request), request))
        else:
            self.sendResponse("500 Server Internal Error")

    def processAck(self):
        destination = self.getDestination()
        if len(destination) > 0:
            if self.client_address == reg_addr:
                client_ip, client_port, token = self.getSocketInfo(destination)
                client_address = (client_ip, client_port)
                request = string.join(self.data, '\r\n')
                self.socket.sendto(request, client_address)
                showtime()
                logging.info("<<< %s" % self.data[0])
                logging.info("---\n<< server sent [%d]:\n%s\n---" % (len(request), request))
            else:
                data = self.removeRouteHeader()
                #insert Record-Route
                data.insert(1, recordRoute)
                request = string.join(data,'\r\n')
                self.socket.sendto(request, reg_addr)
                showtime()
                logging.info(">>> %s" % self.data[0])
                logging.info("---\n>> client sent [%d]:\n%s\n---" % (len(request), request))

    def processNonInvite(self):
        origin = self.getOrigin()
        if len(origin) == 0:
            self.sendResponse("400 Bad Request")
            logging.info()
            return
        destination = self.getDestination()
        if len(destination) > 0:
            if self.client_address == reg_addr:
                client_ip, client_port, token = self.getSocketInfo(destination)
                client_address = (client_ip, client_port)
                request = string.join(self.data, '\r\n')
                self.socket.sendto(request, client_address)
                showtime()
                logging.info("<<< %s" % self.data[0])
                logging.info("---\n<< server sent [%d]:\n%s\n---" % (len(request), request))
            else:
                data = self.removeRouteHeader()
                #insert Record-Route
                data.insert(1, recordRoute)
                request = string.join(data, '\r\n')
                self.socket.sendto(request, reg_addr)
                showtime()
                logging.info(">>> %s" % self.data[0])
                logging.info("---\n>> client sent [%d]:\n%s\n---" % (len(request), request))

        else:
            self.sendResponse("500 Server Internal Error")
            logging.warn("---------------------------------------------------------")
            logging.warn("Server Sent Error to client because destination in uri is ambiguous: %s" % destination)
            logging.warn("---------------------------------------------------------")


    def processBye(self):
        if self.client_address == reg_addr:
            destination = self.getDestination()
            client_ip, client_port, token = self.getSocketInfo(destination)
            client_address = (client_ip, client_port)
            request = string.join(self.data, '\r\n')
            self.socket.sendto(request, client_address)
            showtime()
            logging.info("<<< %s" % self.data[0])
            logging.info("---\n<< server sent [%d]:\n%s\n---" % (len(request), request))
        else:
            data = self.removeRouteHeader()
            data.insert(1, recordRoute)
            request = string.join(data, '\r\n')
            self.socket.sendto(request, reg_addr)
            showtime()
            logging.info(">>> %s" % self.data[0])
            logging.info("---\n>> client sent [%d]:\n%s\n---" % (len(request), request))

    def processCode(self):
        if self.client_address == reg_addr:
            destination = self.getOrigin()
            self.data.insert(1, recordRoute)
            client_ip, client_port, token = self.getSocketInfo(destination)
            client_address = (client_ip, client_port)
            request = string.join(self.data, '\r\n')
            self.socket.sendto(request, client_address)
            showtime()
            logging.info("<<< %s" % self.data[0])
            logging.info("---\n<< server sent [%d]:\n%s\n---" % (len(request), request))
        else:
            self.data.insert(1, recordRoute)
            request = string.join(self.data, '\r\n')
            self.socket.sendto(request, reg_addr)
            showtime()
            logging.info(">>> %s" % self.data[0])
            logging.info("---\n>> client sent [%d]:\n%s\n---" % (len(request), request))


    def processRequest(self):
        #print "processRequest"
        if len(self.data) > 0:
            request_uri = self.data[0]
            logging.info("Received: " + request_uri + " From: " + self.client_address[0] + ":" + str(self.client_address[1]))
            if rx_register.search(request_uri):
                self.processRegister()
            elif rx_invite.search(request_uri):
                self.processInvite()
            elif rx_ack.search(request_uri):
                self.processAck()
            elif rx_bye.search(request_uri):
                self.processBye()
            elif rx_cancel.search(request_uri):
                self.processNonInvite()
            elif rx_options.search(request_uri):
                self.processNonInvite()
            elif rx_info.search(request_uri):
                self.processNonInvite()
            elif rx_message.search(request_uri):
                self.processNonInvite()
            elif rx_refer.search(request_uri):
                self.processNonInvite()
            elif rx_prack.search(request_uri):
                self.processNonInvite()
            elif rx_update.search(request_uri):
                self.processNonInvite()
            elif rx_subscribe.search(request_uri):
                self.processNonInvite()
            elif rx_publish.search(request_uri):
                self.processNonInvite()
            elif rx_notify.search(request_uri):
                self.processNonInvite()
            elif rx_code.search(request_uri):
                self.processCode()
            else:
                logging.error("request_uri %s" % request_uri)
                #print "message %s unknown" % self.data

    def handle(self):
        data = self.request[0]
        self.data = data.split('\r\n')
        self.socket = self.request[1]
        request_uri = self.data[0]
        if rx_request_uri.search(request_uri) or rx_code.search(request_uri):
            showtime()
            self.processRequest()
        else:
            if len(data) > 4:
                showtime()
                logging.warning("---\n>> server received [%d]:" % len(data))
                hexdump(data, ' ', 16)
                logging.warning("---")

if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s', filename='proxy.log', level=logging.INFO, datefmt='%H:%M:%S')
    logging.info(time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime()))
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    recordRoute = "Record-Route: <sip:%s:%d;lr>" % (public_ip, PORT)
    topVia = "Via: SIP/2.0/UDP %s:%d" % (public_ip, PORT)
    server = SocketServer.UDPServer((HOST, PORT), UDPHandler)
    print "Server is running on public ip -> " + public_ip + ":" + str(PORT)
    print "Server is running on private ip -> " + ip_address + ":" + str(PORT)
    timer.start()
    server.serve_forever()