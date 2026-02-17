# Система отпечатков устройств (Fingerprinting)
class DeviceFingerprint:
    def __init__(self):
        self.user_fingerprints = defaultdict(dict)
        
    def generate_fingerprint(self, connection_data):
        """Генерация отпечатка устройства"""
        fingerprint_data = {
            'ip': connection_data.get('ip'),
            'user_agent': connection_data.get('user_agent'),
            'tls_fingerprint': connection_data.get('tls_fingerprint'),
            'tcp_fingerprint': self.get_tcp_fingerprint(connection_data),
            'timezone': connection_data.get('timezone'),
        }
        
        # Создаем хеш отпечатка
        import hashlib
        fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()
    
    def check_device_limit(self, user_id, fingerprint, limit=1):
        """Проверка лимита устройств"""
        if user_id not in self.user_fingerprints:
            self.user_fingerprints[user_id] = {}
        
        user_devices = self.user_fingerprints[user_id]
        
        if fingerprint not in user_devices:
            if len(user_devices) >= limit:
                return False, list(user_devices.keys())
            user_devices[fingerprint] = datetime.now()
        
        return True, None