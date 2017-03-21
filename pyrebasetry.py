import pyrebase

config = {'apiKey': "AIzaSyAlTNQ0rX_z49-EL71e8le0vPew16g8WDg", 'authDomain': "mercurio-development.firebaseapp.com", 'databaseURL': "https://mercurio-development.firebaseio.com", 'storageBucket': "mercurio-development.appspot.com", 'messagingSenderId': "203647142462"}
firebase = pyrebase.initialize_app(config)
email = 'fburgos@optivon.net'
password = 'optivon_787'
auth = firebase.auth()
user = auth.sign_in_with_email_and_password(email, password)
db = firebase.database()
# a = "7873042982@63.131.240.90"
# db.child('test').push(a)
# b = {'ip': '10.10.10.10', 'port': 1010}
# db.child('test').set(user['idToken'])
objects = db.child('test').get()
print not objects.val()
if objects.val():
    for obj in objects.each():
        # db.child('test').child().remove()
        print obj
        print obj.val() != ""
        print obj.val() == ""
        print obj.key()
        db.child('test').child(obj.key()).remove()
print objects.val()

print (objects.val() != "")