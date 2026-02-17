# Система управления устройствами по ОС

class DeviceManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.os_detector = OSDetector()
        self.user_devices: Dict[str, Dict[DeviceOS, DeviceSignature]] = {}
        
    async def check_device_limit(self, user_id: str, connection_data: dict) -> tuple[bool, Optional[str]]:
        """Проверка лимита устройств по типу ОС"""
        
        # Определяем ОС
        detected_os = self.os_detector.detect_os_from_connection(connection_data)
        
        # Создаем отпечаток устройства
        device_fingerprint = self.create_device_fingerprint(connection_data, detected_os)
        
        # Получаем текущие устройства пользователя
        user_devices = self.user_devices.get(user_id, {})
        
        # Проверяем, есть ли уже устройство с этой ОС
        if detected_os in user_devices:
            existing_device = user_devices[detected_os]
            
            # Если это то же устройство - разрешаем
            if existing_device.fingerprint == device_fingerprint:
                existing_device.last_seen = datetime.now()
                return True, None
            
            # Если другое устройство с той же ОС - блокируем
            return False, f"already_exists:{detected_os.value}"
        
        # Добавляем новое устройство
        new_device = DeviceSignature(
            os_type=detected_os,
            ip_address=connection_data.get('ip'),
            fingerprint=device_fingerprint,
            tls_signature=self.extract_tls_signature(connection_data),
            tcp_signature=self.extract_tcp_signature(connection_data),
            first_seen=datetime.now(),
            last_seen=datetime.now()
        )
        
        if user_id not in self.user_devices:
            self.user_devices[user_id] = {}
        
        self.user_devices[user_id][detected_os] = new_device
        
        # Сохраняем в БД
        await self.save_device_to_db(user_id, new_device)
        
        return True, None
    
    def create_device_fingerprint(self, connection_data: dict, os_type: DeviceOS) -> str:
        """Создание уникального отпечатка устройства"""
        fingerprint_data = {
            'os': os_type.value,
            'tls_ciphers': connection_data.get('tls', {}).get('ciphers', []),
            'tls_extensions': connection_data.get('tls', {}).get('extensions', []),
            'tcp_ttl': connection_data.get('tcp', {}).get('ttl'),
            'tcp_window': connection_data.get('tcp', {}).get('window_size'),
            'sni': connection_data.get('sni'),
        }
        
        # Добавляем специфичные для ОС параметры
        if os_type in [DeviceOS.IOS, DeviceOS.MACOS]:
            fingerprint_data['apple_specific'] = connection_data.get('apple_push_token')
        elif os_type == DeviceOS.ANDROID:
            fingerprint_data['android_id'] = connection_data.get('android_id')
        
        fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()