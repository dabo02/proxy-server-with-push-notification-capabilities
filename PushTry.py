import time
from apns import APNs, Frame, Payload

apns = APNs(use_sandbox=True, cert_file='/home/dabo02/Desktop/Projects/Work/VoipPushProto/MercurioVoipPush.pem')

# Send a notification
#token_hex = 'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b87'
#payload = Payload(alert="Tu ere un bobo pa!", sound="default", badge=1)
#apns.gateway_server.send_notification(token_hex, payload)

# Send an iOS 10 compatible notification
token_hex = '94ded1b8278517de1676ed2ef4ad332fd522443d7893328b6055224c48311d98'
payload = Payload(alert="Test", sound="default", badge=1)
apns.gateway_server.send_notification(token_hex, payload)

# Send multiple notifications in a single transmission
#frame = Frame()
#identifier = 1
#expiry = time.time()+3600
#priority = 10
#frame.add_item('b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b87', payload, identifier, expiry, priority)
#apns.gateway_server.send_notification_multiple(frame)
