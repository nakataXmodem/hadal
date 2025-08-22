import aiohttp
import logging
import traceback
from typing import Optional
from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

logger = logging.getLogger(__name__)

class TelegramNotifier:
    def __init__(self):
        self.bot_token = TELEGRAM_BOT_TOKEN
        self.chat_id = TELEGRAM_CHAT_ID
        self.enabled = bool(self.bot_token and self.chat_id)
        
        if not self.enabled:
            logger.warning("Telegram notifications disabled - missing bot token or chat ID")
    
    async def send_message(self, message: str, parse_mode: str = "HTML") -> bool:
        """Send a message to Telegram bot"""
        if not self.enabled:
            return False
            
        try:
            url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
            data = {
                "chat_id": self.chat_id,
                "text": message,
                "parse_mode": parse_mode
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=data, timeout=10) as response:
                    if response.status == 200:
                        logger.info("Telegram notification sent successfully")
                        return True
                    else:
                        logger.error(f"Failed to send Telegram notification: {response.status}")
                        return False
                        
        except Exception as e:
            logger.error(f"Error sending Telegram notification: {e}")
            return False
    
    async def send_error_notification(self, error: Exception, context: str = "", 
                                    additional_info: Optional[dict] = None) -> bool:
        """Send an error notification to Telegram"""
        if not self.enabled:
            return False
            
        try:
            # Format the error message
            error_type = type(error).__name__
            error_message = str(error)
            traceback_text = traceback.format_exc()
            
            # Build the message
            message_parts = [
                f"🚨 <b>Error Alert</b>",
                f"<b>Context:</b> {context}",
                f"<b>Error Type:</b> {error_type}",
                f"<b>Error Message:</b> {error_message}"
            ]
            
            if additional_info:
                for key, value in additional_info.items():
                    message_parts.append(f"<b>{key}:</b> {value}")
            
            # Add traceback (truncated if too long)
            if traceback_text:
                # Telegram has a 4096 character limit, so truncate if needed
                max_traceback_length = 2000
                if len(traceback_text) > max_traceback_length:
                    traceback_text = traceback_text[:max_traceback_length] + "\n... (truncated)"
                message_parts.append(f"<b>Traceback:</b>\n<code>{traceback_text}</code>")
            
            message = "\n".join(message_parts)
            
            return await self.send_message(message)
            
        except Exception as e:
            logger.error(f"Error formatting Telegram notification: {e}")
            return False

# Global instance
telegram_notifier = TelegramNotifier()
