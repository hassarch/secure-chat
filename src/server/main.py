"""
SecureChat Relay Server

Main entry point for the WebSocket relay server.
"""

import asyncio
import logging
import signal
import sys
from pathlib import Path

import websockets

from src.server.database import Database
from src.server.handler import MessageHandler


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('securechat_server.log')
    ]
)

logger = logging.getLogger(__name__)


# Server configuration
HOST = '0.0.0.0'
PORT = 8000
DATABASE_PATH = 'securechat.db'


class SecureChatServer:
    """
    WebSocket relay server for SecureChat.
    """
    
    def __init__(self, host: str = HOST, port: int = PORT, db_path: str = DATABASE_PATH):
        """
        Initialize the server.
        
        Args:
            host: Host to bind to
            port: Port to listen on
            db_path: Path to SQLite database
        """
        self.host = host
        self.port = port
        self.db = Database(db_path)
        self.handler = MessageHandler(self.db)
        self.server = None
        self.cleanup_task = None
        self.running = False
    
    async def start(self):
        """Start the WebSocket server"""
        logger.info(f"Starting SecureChat relay server on {self.host}:{self.port}")
        logger.info(f"Database: {self.db.db_path}")
        
        # Start the WebSocket server
        self.server = await websockets.serve(
            self.handler.handle_connection,
            self.host,
            self.port
        )
        
        # Start background cleanup task
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        self.running = True
        logger.info("Server started successfully")
        
        # Print stats
        stats = self.db.get_stats()
        logger.info(f"Database stats: {stats}")
    
    async def stop(self):
        """Stop the server gracefully"""
        logger.info("Stopping server...")
        self.running = False
        
        # Cancel cleanup task
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        
        # Close WebSocket server
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        logger.info("Server stopped")
    
    async def _cleanup_loop(self):
        """Background task to cleanup expired messages"""
        while self.running:
            try:
                await asyncio.sleep(3600)  # Run every hour
                
                deleted = self.db.cleanup_expired_messages()
                if deleted > 0:
                    logger.info(f"Cleaned up {deleted} expired messages")
                
                # Log stats
                stats = self.db.get_stats()
                logger.info(f"Server stats: {stats}")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}", exc_info=True)
    
    async def run(self):
        """Run the server until interrupted"""
        await self.start()
        
        # Setup signal handlers
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(self.stop()))
        
        # Keep running
        try:
            await asyncio.Future()  # Run forever
        except asyncio.CancelledError:
            pass
        finally:
            await self.stop()


async def main():
    """Main entry point"""
    # Parse command line arguments (simple version)
    import argparse
    
    parser = argparse.ArgumentParser(description='SecureChat Relay Server')
    parser.add_argument('--host', default=HOST, help=f'Host to bind to (default: {HOST})')
    parser.add_argument('--port', type=int, default=PORT, help=f'Port to listen on (default: {PORT})')
    parser.add_argument('--database', default=DATABASE_PATH, help=f'Database path (default: {DATABASE_PATH})')
    
    args = parser.parse_args()
    
    # Create and run server
    server = SecureChatServer(args.host, args.port, args.database)
    
    try:
        await server.run()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped by user")
        sys.exit(0)
