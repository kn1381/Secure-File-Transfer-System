import asyncio
import json
import time
import uuid

HOST = "127.0.0.1"
PORT = 5050
MAX_LINE = 64 * 1024  # حداکثر طول یک پیام (یک خط)


async def send_msg(writer: asyncio.StreamWriter, obj: dict) -> None:
    """ارسال یک شیء JSON به‌صورت یک خط (JSONL)."""
    data = (
        json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        + b"\n"
    )
    writer.write(data)
    await writer.drain()


async def recv_msg(reader: asyncio.StreamReader) -> dict | None:
    """دریافت یک خط JSON. اگر ارتباط قطع شده باشد، None برمی‌گرداند."""
    line = await reader.readline()
    if not line:
        return None
    if len(line) > MAX_LINE:
        raise ValueError("message too long")
    try:
        return json.loads(line.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"bad json: {e}")


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    session_id = str(uuid.uuid4())
    print(f"[+] client connected {peer}, session={session_id}")

    try:
        while True:
            msg = await recv_msg(reader)
            if msg is None:
                break  # connection closed

            op = msg.get("op")
            seq = msg.get("seq")
            payload = msg.get("payload", {})

            try:
                if op == "ping":
                    resp = {
                        "type": "response",
                        "op": op,
                        "ok": True,
                        "seq": seq,
                        "payload": {"msg": "pong", "server_time": time.time()},
                    }
                    await send_msg(writer, resp)

                elif op == "echo":
                    text = str(payload.get("text", ""))
                    resp = {
                        "type": "response",
                        "op": op,
                        "ok": True,
                        "seq": seq,
                        "payload": {"text": text},
                    }
                    await send_msg(writer, resp)

                elif op == "quit":
                    await send_msg(
                        writer,
                        {
                            "type": "response",
                            "op": op,
                            "ok": True,
                            "seq": seq,
                            "payload": {"msg": "bye"},
                        },
                    )
                    break

                else:
                    await send_msg(
                        writer,
                        {
                            "type": "error",
                            "op": op,
                            "ok": False,
                            "seq": seq,
                            "error": "unknown_op",
                        },
                    )

            except Exception as inner:
                await send_msg(
                    writer,
                    {
                        "type": "error",
                        "op": op,
                        "ok": False,
                        "seq": seq,
                        "error": f"op_failed: {inner}",
                    },
                )

    except Exception as e:
        print(f"[!] error with {peer}: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        print(f"[-] client disconnected {peer}, session={session_id}")


async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    addr = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    print(f"Server listening on {addr}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped.")
