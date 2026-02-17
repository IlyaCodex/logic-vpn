# Интеграция с xRay и мониторинг

import asyncio
from typing import Dict, List
import sqlite3
import grpc

class XRayOSLimiter:
    def __init__(self, xray_config: str, bot):
        self.xray_config = xray_config
        self.bot = bot
        self.device_manager = DeviceManager("devices.db")
        self.blocked_connections: Dict[str, List[str]] = {}
        
    async def monitor_connections(self):
        """Главный цикл мониторинга подключений"""
        while True:
            try:
                # Получаем активные подключения из xRay
                connections = await self.get_active_connections()
                
                for user_id, conn_list in connections.items():
                    await self.process_user_connections(user_id, conn_list)
                    
            except Exception as e:
                print(f"Monitoring error: {e}")
                
            await asyncio.sleep(2)  # Проверяем каждые 2 секунды
    
    async def get_active_connections(self) -> Dict[str, List[dict]]:
        """Получение активных подключений из xRay через API"""
        connections = {}
        
        # Парсим логи xRay или используем API
        # Здесь нужно извлечь TLS/TCP информацию
        with open('/var/log/xray/access.log', 'r') as f:
            for line in f.readlines()[-1000:]:  # Последние 1000 строк
                conn_data = self.parse_connection_log(line)
                if conn_data:
                    user_id = conn_data.get('user_id')
                    if user_id not in connections:
                        connections[user_id] = []
                    connections[user_id].append(conn_data)
        
        return connections
    
    def parse_connection_log(self, log_line: str) -> Optional[dict]:
        """Парсинг строки лога для извлечения данных подключения"""
        import re
        
        # Парсим данные подключения из лога xRay
        # Формат зависит от настроек логирования
        pattern = r'(\d+\.\d+\.\d+\.\d+):(\d+).*user:$$([\w-]+)$$.*tls:(\{.*?\}).*tcp:(\{.*?\})'
        match = re.search(pattern, log_line)
        
        if match:
            return {
                'ip': match.group(1),
                'port': match.group(2),
                'user_id': match.group(3),
                'tls': json.loads(match.group(4)),
                'tcp': json.loads(match.group(5)),
                'timestamp': datetime.now()
            }
        return None
    
    async def process_user_connections(self, user_id: str, connections: List[dict]):
        """Обработка подключений пользователя"""
        os_devices = {}
        
        for conn in connections:
            # Проверяем лимит устройства
            allowed, reason = await self.device_manager.check_device_limit(user_id, conn)
            
            if not allowed:
                # Блокируем подключение
                await self.block_connection(user_id, conn, reason)
                
                # Уведомляем пользователя
                await self.notify_user_blocked(user_id, conn, reason)
            else:
                # Определяем ОС для статистики
                os_type = self.device_manager.os_detector.detect_os_from_connection(conn)
                os_devices[os_type] = conn
        
        # Обновляем статистику пользователя
        await self.update_user_stats(user_id, os_devices)
    
    async def block_connection(self, user_id: str, connection: dict, reason: str):
        """Блокировка конкретного подключения"""
        
        # Создаем правило блокировки для xRay
        block_rule = {
            "type": "field",
            "ip": [connection['ip']],
            "user": [user_id],
            "outboundTag": "blocked"
        }
        
        # Применяем правило через xRay API
        await self.apply_xray_rule(block_rule)
        
        # Сохраняем в список заблокированных
        if user_id not in self.blocked_connections:
            self.blocked_connections[user_id] = []
        self.blocked_connections[user_id].append(connection['ip'])