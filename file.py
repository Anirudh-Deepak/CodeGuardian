# 🔴 CRITICAL (AWS + Private Key)
aws_key = "AKIAIOSFODNN7EXAMPLE"
private_key = "-----BEGIN PRIVATE KEY-----"

# 🟠 HIGH (API Keys)
API_KEY = "sk-abc123XYZ789SECRETKEY"
client_key = "pk_live_51H8abcdEFGHijklMNOP"

# 🟡 MEDIUM (Password + Token)
password = "MySecurePassword123"
token = "ghp_1234567890abcdefABCDEF123456"

# 🔥 Entropy-based (unknown secrets)
random_secret = "x7F9kL2pQwZ8mN3rT5yU6vB1"
another_secret = "ZxY987654321ABCdefGHIJKLM"

# 🔁 Duplicate (should be merged)
API_KEY = "sk-duplicate123SECRET"
key = "sk-duplicate123SECRET"

# ❌ Should NOT be detected (noise)
username = "admin"
key = "hello123"
debug_value = "test"
