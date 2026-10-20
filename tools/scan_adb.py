import asyncio
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.100"  # example; pass the phone IP
START = 30000
END = 65535
CONCURRENCY = 800
TIMEOUT = 0.6

sem = asyncio.Semaphore(CONCURRENCY)


async def probe(port: int):
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(HOST, port), TIMEOUT
            )
        except Exception:
            return None
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port


async def main():
    tasks = [asyncio.create_task(probe(p)) for p in range(START, END + 1)]
    open_ports = []
    for fut in asyncio.as_completed(tasks):
        port = await fut
        if port is not None:
            open_ports.append(port)
            print(port, flush=True)
    print("done", sorted(open_ports), file=sys.stderr)


asyncio.run(main())
