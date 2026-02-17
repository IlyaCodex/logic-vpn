#  Мониторинг через xRay API и статистику
import json
import asyncio
from datetime import datetime
from collections import defaultdict

class DeviceLimiter:
    def __init__(self, xray_api_port=10085):
        self.api_port = xray_api_port
        self.user_devices = defaultdict(set)  # user_id -> set of IPs
        self.device_limits = {}  # user_id -> limit
        
    async def monitor_connections(self):
        """Мониторинг активных подключений"""
        while True:
            try:
                # Получаем статистику через xRay API
                stats = await self.get_xray_stats()
                
                for user_id, connections in stats.items():
                    unique_ips = set()
                    
                    for conn in connections:
                        # Собираем уникальные IP адреса
                        unique_ips.add(conn['ip'])
                    
                    # Проверяем лимит
                    limit = self.device_limits.get(user_id, 1)
                    
                    if len(unique_ips) > limit:
                        # Превышен лимит устройств
                        await self.handle_limit_exceeded(user_id, unique_ips, limit)
                    
                    self.user_devices[user_id] = unique_ips
                
            except Exception as e:
                print(f"Monitoring error: {e}")
            
            await asyncio.sleep(5)  # Проверяем каждые 5 секунд
    
    async def get_xray_stats(self):
        """Получение статистики через gRPC API xRay"""
        # Используем xray-api для получения статистики
        import grpc
        from xray_api import StatsServiceStub
        
        channel = grpc.insecure_channel(f'localhost:{self.api_port}')
        stub = StatsServiceStub(channel)
        
        # Получаем список активных пользователей
        response = stub.QueryStats(...)
        return self.parse_stats(response)