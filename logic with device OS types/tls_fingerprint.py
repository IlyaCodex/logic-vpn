# Определение ОС через TLS Fingerprinting и сетевые характеристики

import hashlib
import json
from enum import Enum
from typing import Dict, Optional, Set
from dataclasses import dataclass
from datetime import datetime

class DeviceOS(Enum):
    IOS = "ios"
    MACOS = "macos"
    ANDROID = "android"
    WINDOWS = "windows"
    LINUX = "linux"
    UNKNOWN = "unknown"

@dataclass
class DeviceSignature:
    os_type: DeviceOS
    ip_address: str
    fingerprint: str
    tls_signature: str
    tcp_signature: str
    first_seen: datetime
    last_seen: datetime
    is_active: bool = True

class OSDetector:
    def __init__(self):
        # TLS signatures для разных ОС
        self.tls_patterns = {
            DeviceOS.IOS: {
                'ciphers': [
                    'TLS_AES_128_GCM_SHA256',
                    'TLS_AES_256_GCM_SHA384',
                    'TLS_CHACHA20_POLY1305_SHA256'
                ],
                'extensions': ['0x0017', '0x0000', '0x0023'],
                'curves': ['x25519', 'secp256r1', 'secp384r1'],
                'alpn': ['h2', 'http/1.1'],
                'versions': ['TLS 1.3', 'TLS 1.2']
            },
            DeviceOS.ANDROID: {
                'ciphers': [
                    'TLS_AES_128_GCM_SHA256',
                    'TLS_AES_256_GCM_SHA384',
                    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'
                ],
                'extensions': ['0x0000', '0x0017', '0x0010'],
                'curves': ['x25519', 'secp256r1'],
                'alpn': ['h2', 'http/1.1'],
                'versions': ['TLS 1.3', 'TLS 1.2']
            },
            DeviceOS.WINDOWS: {
                'ciphers': [
                    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                    'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256'
                ],
                'extensions': ['0x0000', '0x0023', '0x0017', '0x0033'],
                'curves': ['secp256r1', 'secp384r1'],
                'alpn': ['h2', 'http/1.1'],
                'versions': ['TLS 1.2', 'TLS 1.3']
            },
            DeviceOS.MACOS: {
                'ciphers': [
                    'TLS_AES_128_GCM_SHA256',
                    'TLS_AES_256_GCM_SHA384',
                    'TLS_CHACHA20_POLY1305_SHA256'
                ],
                'extensions': ['0x0017', '0x0000', '0x0023', '0x0010'],
                'curves': ['x25519', 'secp256r1', 'secp384r1', 'secp521r1'],
                'alpn': ['h2', 'http/1.1'],
                'versions': ['TLS 1.3', 'TLS 1.2']
            }
        }
        
        # TCP/IP характеристики для разных ОС
        self.tcp_patterns = {
            DeviceOS.IOS: {
                'ttl': [64, 255],
                'window_size': [65535, 131072],
                'tcp_options': ['mss', 'sackOK', 'timestamps', 'nop', 'wscale']
            },
            DeviceOS.ANDROID: {
                'ttl': [64, 127],
                'window_size': [65535, 131072, 262144],
                'tcp_options': ['mss', 'sackOK', 'timestamps', 'nop', 'wscale']
            },
            DeviceOS.WINDOWS: {
                'ttl': [128],
                'window_size': [65535, 8192],
                'tcp_options': ['mss', 'nop', 'wscale', 'sackOK', 'timestamps']
            },
            DeviceOS.MACOS: {
                'ttl': [64],
                'window_size': [65535, 131072],
                'tcp_options': ['mss', 'nop', 'wscale', 'nop', 'nop', 'timestamps', 'sackOK']
            }
        }
    
    def detect_os_from_connection(self, connection_data: dict) -> DeviceOS:
        """Определение ОС по данным подключения"""
        
        # Получаем TLS fingerprint
        tls_data = connection_data.get('tls', {})
        tcp_data = connection_data.get('tcp', {})
        
        scores = {os: 0 for os in DeviceOS if os != DeviceOS.UNKNOWN}
        
        # Анализируем TLS параметры
        if tls_data:
            for os_type, patterns in self.tls_patterns.items():
                score = self._calculate_tls_score(tls_data, patterns)
                scores[os_type] += score
        
        # Анализируем TCP параметры
        if tcp_data:
            for os_type, patterns in self.tcp_patterns.items():
                score = self._calculate_tcp_score(tcp_data, patterns)
                scores[os_type] += score
        
        # Дополнительные проверки по SNI и User-Agent
        sni = connection_data.get('sni', '')
        if 'apple' in sni.lower() or 'icloud' in sni.lower():
            scores[DeviceOS.IOS] += 10
            scores[DeviceOS.MACOS] += 5
        elif 'android' in sni.lower() or 'google' in sni.lower():
            scores[DeviceOS.ANDROID] += 10
        elif 'windows' in sni.lower() or 'microsoft' in sni.lower():
            scores[DeviceOS.WINDOWS] += 10
        
        # Возвращаем ОС с максимальным счетом
        if max(scores.values()) > 0:
            return max(scores, key=scores.get)
        return DeviceOS.UNKNOWN
    
    def _calculate_tls_score(self, tls_data: dict, patterns: dict) -> int:
        """Расчет схожести TLS отпечатка"""
        score = 0
        
        # Проверяем шифры
        client_ciphers = tls_data.get('ciphers', [])
        for cipher in patterns.get('ciphers', []):
            if cipher in client_ciphers:
                score += 2
        
        # Проверяем расширения
        client_extensions = tls_data.get('extensions', [])
        for ext in patterns.get('extensions', []):
            if ext in client_extensions:
                score += 1
        
        # Проверяем curves
        client_curves = tls_data.get('curves', [])
        for curve in patterns.get('curves', []):
            if curve in client_curves:
                score += 2
        
        return score
    
    def _calculate_tcp_score(self, tcp_data: dict, patterns: dict) -> int:
        """Расчет схожести TCP параметров"""
        score = 0
        
        # TTL
        ttl = tcp_data.get('ttl')
        if ttl and ttl in patterns.get('ttl', []):
            score += 5
        
        # Window size
        window = tcp_data.get('window_size')
        if window and window in patterns.get('window_size', []):
            score += 3
        
        return score