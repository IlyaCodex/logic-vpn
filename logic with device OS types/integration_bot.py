# Telegram бот с управлением по ОС

from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext

class VPNBotWithOSLimit:
    def __init__(self, token: str):
        self.bot = Bot(token=token)
        self.dp = Dispatcher()
        self.limiter = XRayOSLimiter("config.json", self.bot)
        self.setup_handlers()
        
    def setup_handlers(self):
        @self.dp.message(Command("status"))
        async def show_status(message: types.Message):
            user_id = await self.get_user_vpn_id(message.from_user.id)
            devices = self.limiter.device_manager.user_devices.get(user_id, {})
            
            text = "📱 <b>Ваши подключенные устройства:</b>\n\n"
            
            os_emoji = {
                DeviceOS.IOS: "🍎",
                DeviceOS.ANDROID: "🤖",
                DeviceOS.WINDOWS: "🪟",
                DeviceOS.MACOS: "💻",
                DeviceOS.LINUX: "🐧"
            }
            
            if devices:
                for os_type, device in devices.items():
                    emoji = os_emoji.get(os_type, "❓")
                    text += f"{emoji} <b>{os_type.value.upper()}</b>\n"
                    text += f"   IP: {device.ip_address}\n"
                    text += f"   Подключено: {device.first_seen.strftime('%d.%m %H:%M')}\n"
                    text += f"   Активность: {device.last_seen.strftime('%d.%m %H:%M')}\n\n"
            else:
                text += "Нет активных устройств\n\n"
            
            text += "ℹ️ <i>Лимит: 1 устройство на каждую ОС</i>\n"
            text += "💳 Купить дополнительные слоты: /buy_slots"
            
            await message.answer(text, parse_mode="HTML")
        
        @self.dp.message(Command("devices"))
        async def manage_devices(message: types.Message):
            user_id = await self.get_user_vpn_id(message.from_user.id)
            devices = self.limiter.device_manager.user_devices.get(user_id, {})
            
            keyboard = types.InlineKeyboardMarkup(inline_keyboard=[])
            
            for os_type, device in devices.items():
                keyboard.inline_keyboard.append([
                    types.InlineKeyboardButton(
                        text=f"🗑 Отключить {os_type.value}",
                        callback_data=f"remove_device:{os_type.value}"
                    )
                ])
            
            keyboard.inline_keyboard.append([
                types.InlineKeyboardButton(
                    text="🔄 Обновить",
                    callback_data="refresh_devices"
                )
            ])
            
            await message.answer(
                "🔧 Управление устройствами:",
                reply_markup=keyboard
            )
    
    async def notify_user_blocked(self, user_id: str, connection: dict, reason: str):
        """Уведомление о блокировке"""
        telegram_id = await self.get_telegram_id(user_id)
        
        os_type = self.limiter.device_manager.os_detector.detect_os_from_connection(connection)
        
        if "already_exists" in reason:
            os_name = reason.split(":")[1]
            text = (
                f"⛔ <b>Подключение заблокировано!</b>\n\n"
                f"Обнаружена попытка подключения второго устройства {os_name.upper()}\n"
                f"IP: {connection['ip']}\n\n"
                f"На вашем тарифе разрешено только 1 устройство каждого типа.\n\n"
                f"Варианты решения:\n"
                f"1️⃣ Отключите текущее {os_name.upper()} устройство\n"
                f"2️⃣ Купите дополнительный слот для {os_name.upper()}\n"
            )
            
            keyboard = types.InlineKeyboardMarkup(inline_keyboard=[
                [types.InlineKeyboardButton(
                    text=f"💳 Купить слот {os_name.upper()} (299₽)",
                    callback_data=f"buy_os_slot:{os_name}"
                )],
                [types.InlineKeyboardButton(
                    text="📱 Управление устройствами",
                    callback_data="manage_devices"
                )]
            ])
            
            await self.bot.send_message(
                telegram_id,
                text,
                reply_markup=keyboard,
                parse_mode="HTML"
            )