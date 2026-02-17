# Интеграция с Telegram ботом

from aiogram import Bot, Dispatcher, types
from aiogram.fsm.storage.memory import MemoryStorage

class VPNBot:
    def __init__(self, token):
        self.bot = Bot(token=token)
        self.dp = Dispatcher(storage=MemoryStorage())
        self.limiter = DeviceLimiter()
        self.db = Database()  # Ваша БД
        
    async def handle_limit_exceeded(self, user_id, devices, limit):
        """Обработка превышения лимита"""
        telegram_id = await self.db.get_telegram_id(user_id)
        
        # Блокируем лишние подключения
        await self.block_excess_connections(user_id, devices, limit)
        
        # Отправляем уведомление
        keyboard = types.InlineKeyboardMarkup(inline_keyboard=[
            [types.InlineKeyboardButton(
                text="🔐 Купить дополнительное устройство",
                callback_data=f"buy_device:{user_id}"
            )]
        ])
        
        message = (
            "⚠️ <b>Превышен лимит устройств!</b>\n\n"
            f"Ваш тариф: {limit} устройство(а)\n"
            f"Обнаружено: {len(devices)} устройств\n\n"
            "Для подключения дополнительных устройств "
            "необходимо приобрести расширение."
        )
        
        await self.bot.send_message(
            telegram_id, 
            message,
            reply_markup=keyboard,
            parse_mode="HTML"
        )
    
    async def block_excess_connections(self, user_id, devices, limit):
        """Блокировка лишних подключений"""
        devices_list = list(devices)
        allowed_devices = devices_list[:limit]
        blocked_devices = devices_list[limit:]
        
        for device_ip in blocked_devices:
            # Добавляем IP в черный список для этого пользователя
            await self.add_to_firewall(user_id, device_ip)