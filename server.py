import os
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

def get_password_from_key_file():
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        key_file_path = os.path.join(script_dir, "FTP.key")
        with open(key_file_path, 'r') as file:
            password = file.readline().strip()
            return password
    except Exception as e:
        print(f"Error reading password from key file: {e}")
        return None

def start_ftp_server():
    # Kullanıcı yetkilendirme
    authorizer = DummyAuthorizer()
    
    # Şifreyi INFO.key dosyasından al
    password = get_password_from_key_file()
    if not password:
        print("Şifre alınamadı, FTP sunucusu başlatılamıyor.")
        return
    
    # Sadece root kullanıcısına izin ver
    authorizer.add_user("INFO", password, "G:/FTP/INFO", perm="elradfmw")

    # FTP sunucusunu başlat
    handler = FTPHandler
    handler.authorizer = authorizer
    
    server = FTPServer(('0.0.0.0', 21), handler)
    
    print("FTP sunucusu başlatıldı.")
    server.serve_forever()

if __name__ == "__main__":
    start_ftp_server()
