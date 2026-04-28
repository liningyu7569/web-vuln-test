import requests
import base64
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

SERVER_URL = "http://localhost:8077"

def main():
    print("[*] 1. 向 Go 服务端请求公钥...")
    response = requests.get(f"{SERVER_URL}/public-key")
    pub_key_pem = response.text
    print(f"[+] 成功拿到公钥！(截取前60字): \n{pub_key_pem[:60]}...\n")

    # 2. 将拿到的 PEM 字符串解析为 RSA 公钥对象
    public_key = RSA.import_key(pub_key_pem)
    
    # 初始化加密器 (使用与 Go 服务端一致的 PKCS1_v1_5 填充模式)
    cipher_rsa = PKCS1_v1_5.new(public_key)

    # 3. 发送的信息 (必须转换为字节)
    message = "Target located. Commencing operation."
    print(f"[*] 2. 准备发送的机密明文: '{message}'")
    message_bytes = message.encode('utf-8')

    # 4. 执行 RSA 公钥加密！
    ciphertext_bytes = cipher_rsa.encrypt(message_bytes)
    
    # 将二进制密文转为 Base64，方便在 JSON 网络中传输
    ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode('utf-8')

    # 5. 提取密文的 SHA-256 哈希
    sha256_hash = hashlib.sha256(ciphertext_bytes).hexdigest()
    print(f"[*] 3. 计算密文的 SHA-256 哈希作为防伪标签: {sha256_hash}")

    # 6. 打包发送给服务端
    payload = {
        "ciphertext": ciphertext_b64,
        "hash": sha256_hash
    }

    print("[*] 4. 密文与哈希打包完毕，正在通过 POST 发射...")
    res = requests.post(f"{SERVER_URL}/secure-message", json=payload)

    print(f"\n[+] 收到服务端响应: {res.text}")

if __name__ == "__main__":
    main()