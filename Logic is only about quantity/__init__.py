# Полная реализация системы контроля

import asyncio
import aiohttp
import json
from typing import Dict, Set, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta

@dataclass
class DeviceInfo:
    ip: str
    first_seen: datetime
    last_seen: datetime
    fingerprint: str
    blocked: bool = False

class XRayDeviceController:
    def __init__(self, xray_config_path: str, bot_token: str):
        self.config_path = xray_config_path
        self.bot_token = bot_token
        self.user_devices: Dict[str, Set[DeviceInfo]] = {}
        self.user_limits: Dict[str, int] = {}
        
    async def start_monitoring(self):
        """Запуск системы мониторинга"""
        tasks = [
            self.monitor_connections(),
            self.cleanup_old_devices(),
            self.sync_with_xray()
        ]
        await asyncio.gather(*tasks)
    
    async def monitor_connections(self):
        """Основной цикл мониторинга"""
        while True:
            try:
                # Парсим логи xRay для получения подключений
                connections = await self.parse_xray_logs()
                
                for user_id, conn_data in connections.items():
                    await self.process_user_connections(user_id, conn_data)
                    
            except Exception as e:
                print(f"Monitor error: {e}")
                
            await asyncio.sleep(3)
    
    async def process_user_connections(self, user_id: str, connections: list):
        """Обработка подключений пользователя"""
        current_devices = set()
        
        for conn in connections:
            device = DeviceInfo(
                ip=conn['ip'],
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                fingerprint=self.generate_fingerprint(conn)
            )
            current_devices.add(device)
        
        # Проверяем лимит
        limit = self.user_limits.get(user_id, 1)
        
        if len(current_devices) > limit:
            # Сортируем по времени подключения
            sorted_devices = sorted(
                current_devices, 
                key=lambda x: x.first_seen
            )
            
            # Блокируем лишние
            for device in sorted_devices[limit:]:
                await self.block_device(user_id, device)
                await self.notify_user(user_id, device, limit)
        
        self.user_devices[user_id] = current_devices
    
    async def block_device(self, user_id: str, device: DeviceInfo):
        """Блокировка устройства через xRay API"""
        # Добавляем правило в routing для блокировки
        rule = {
            "type": "field",
            "source": [device.ip],
            "user": [user_id],
            "outboundTag": "blocked"
        }
        
        await self.add_routing_rule(rule)
        device.blocked = True
    
    async def add_routing_rule(self, rule: dict):
        """Добавление правила маршрутизации в xRay"""
        # Используем xRay API для добавления правила
        async with aiohttp.ClientSession() as session:
            async with session.post(
                'http://localhost:10085/v1/routing/rules',
                json=rule
            ) as resp:
                return await resp.json()
    
    async def notify_user(self, user_id: str, device: DeviceInfo, limit: int):
        """Отправка уведомления пользователю"""
        telegram_id = await self.get_telegram_id(user_id)
        
        message = (
            f"⚠️ Превышен лимит подключений!\n\n"
            f"Текущий лимит: {limit} устройств\n"
            f"Заблокировано устройство: {device.ip}\n\n"
            f"💳 Купить дополнительное подключение: /buy_device"
        )
        
        async with aiohttp.ClientSession() as session:
            await session.post(
                f'https://api.telegram.org/bot{self.bot_token}/sendMessage',
                json={
                    'chat_id': telegram_id,
                    'text': message,
                    'parse_mode': 'HTML'
                }
            )
    
    def generate_fingerprint(self, connection_data: dict) -> str:
        """Генерация уникального отпечатка устройства"""
        import hashlib
        
        # Собираем уникальные параметры
        fingerprint_data = {
            'ip': connection_data.get('ip'),
            'port': connection_data.get('port'),
            'cipher': connection_data.get('cipher'),
            'sni': connection_data.get('sni'),
            'alpn': connection_data.get('alpn'),
        }
        
        fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()