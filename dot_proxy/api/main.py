import asyncio
import os
import ssl

UPSTREAM_HOST = os.getenv("UPSTREAM_HOST", "172.30.0.20")
UPSTREAM_PORT = int(os.getenv("UPSTREAM_PORT", "53"))
LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "853"))
CERT_PATH = os.getenv("CERT_PATH", "/certs/dot.pem")
KEY_PATH = os.getenv("KEY_PATH", "/certs/dot.key")


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def handle_client(
    client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
) -> None:
    try:
        upstream_reader, upstream_writer = await asyncio.open_connection(
            UPSTREAM_HOST, UPSTREAM_PORT
        )
    except Exception:
        try:
            client_writer.close()
            await client_writer.wait_closed()
        except Exception:
            pass
        return

    task_a = asyncio.create_task(pipe(client_reader, upstream_writer))
    task_b = asyncio.create_task(pipe(upstream_reader, client_writer))

    done, pending = await asyncio.wait(
        {task_a, task_b}, return_when=asyncio.FIRST_COMPLETED
    )
    for task in pending:
        task.cancel()


async def main() -> None:
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(certfile=CERT_PATH, keyfile=KEY_PATH)

    server = await asyncio.start_server(
        handle_client,
        host=LISTEN_HOST,
        port=LISTEN_PORT,
        ssl=ssl_ctx,
    )
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
