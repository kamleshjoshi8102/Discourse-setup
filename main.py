from flask import Flask, render_template, request, redirect, url_for
import hmac
import hashlib
import base64
import urllib.parse


key = "KAMLESHJOSHI"


def encode_to_hmac_sha256(key, message):
    hmac_hash = hmac.new(key.encode('utf-8'), message.encode('utf-8'), hashlib.sha256)
    return hmac_hash.hexdigest()

app = Flask(__name__)



@app.route('/')
def index():
    sso = request.args.get('sso')
    sig = request.args.get('sig')

    # print(type(sso))

    encoded_hmac = encode_to_hmac_sha256(key,sso)

    if(sig == encoded_hmac):
        print("Sender is discource authentication Complete!!")

    decrypted_sso = base64.b64decode(sso).decode('utf-8')
    
    print(decrypted_sso)

    # data = "nonce=e6789c11926c1b890deb07a168db91ca&return_sso_url=http%3A%2F%2Flocalhost%3A4200%2Fsession%2Fsso_login"
    
    
    nonce = [part.split('=')[1] for part in decrypted_sso.split('&') if part.startswith('nonce=')][0]

    print("Nonce:", nonce)
    
    
    string_to_encrypt = f"nonce={nonce}&email=j.kamlesh8102@gmail.com&external_id=2"
    
    print(string_to_encrypt)

    print(type(string_to_encrypt))

    encrypt_hmac_ssobase64 = base64.b64encode(urllib.parse.quote(string_to_encrypt).encode('utf-8'))

    print(encrypt_hmac_ssobase64)

    new_sig = encrypt_hmac_ssobase64

    encrypt_hmac_ssobase64 = urllib.parse.quote(new_sig)

    print(encrypt_hmac_ssobase64)

    # encrypt_hmac_sso = encode_to_hmac_sha256(key, encrypt_hmac_ssobase64)
     
    new_sig = encode_to_hmac_sha256(key,new_sig.decode('utf-8'))

    redirect_url = f"http://localhost:4201/session/sso_login?sso={encrypt_hmac_ssobase64}&sig={new_sig}"

    print(redirect_url)

    return redirect(redirect_url)


  

    # return render_template('login.html')

# Parameters: {"sso"=>"bm9uY2UlM0RiMmMzNTRjOWFjMWYzMDVhMDI5YzM0YmZhNmUzYmZlMyUyNmVtYWlsJTNEai5rYW1sZXNoODEwMiU0MGdtYWlsLmNvbSUyNmV4dGVybmFsX2lkJTNEMg==", 

# "sig"=>"f4faddb525daa767f45b3b86c604a041eef5713851e6095ac66256e5eceb66dd"}

# Base64 encode payload
# Calculate a HMAC-SHA256 hash of the payload using discourse_connect_secret as the key and Base64 encoded payload as text
# Redirect back to the return_sso_url with an sso and sig query parameter (http://discourse_site/session/sso_login?sso=payload&sig=sig)
 
if __name__ == '__main__':
    app.run(debug=True)
