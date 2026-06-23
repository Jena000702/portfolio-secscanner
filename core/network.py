import asyncio
import socket

class AsyncNetworkScanner:
    def __init__(self, target, ports):
        self.target = target
        self.ports = ports

    async def scan_port(self, port):
        try:
            # Resolve target hostname to handle domains like scanme.nmap.org
            loop = asyncio.get_running_loop()
            target_ip = await loop.run_in_executor(None, socket.gethostbyname, self.target)
            
            # Open an asynchronous TCP connection handshake
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, port), timeout=1.5
            )
            
            # Simple banner grab attempt if connection opens successfully
            banner = "Unknown Service"
            try:
                writer.write(b"HEAD / HTTP/1.1\r\n\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(100), timeout=1.0)
                if data:
                    banner = data.decode('utf-8', errors='ignore').split('\n')[0].strip()
            except Exception:
                pass
                
            writer.close()
            await writer.wait_closed()
            return {"port": port, "status": "OPEN", "banner": banner}
        except Exception:
            return None

    async def run(self):
        # Build task array for parallel async execution
        tasks = [self.scan_port(port) for port in self.ports]
        results = await asyncio.gather(*tasks)
        # Filter out failed connections (None responses)
        return [r for r in results if r is not None]
