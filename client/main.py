import asyncio
import json
import argparse

MAX_LINE = 64 * 1024


async def send_msg(writer: asyncio.StreamWriter, obj: dict) -> None:
    data = (
        json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        + b"\n"
    )
    writer.write(data)
    await writer.drain()


async def recv_msg(reader: asyncio.StreamReader) -> dict | None:
    line = await reader.readline()
    if not line:
        return None
    if len(line) > MAX_LINE:
        raise ValueError("message too long")
    return json.loads(line.decode("utf-8"))


async def repl(host: str, port: int):
    reader, writer = await asyncio.open_connection(host, port)
    print(f"Connected to {host}:{port}. Type commands: ping | echo <text> | quit")
    seq = 1

    try:
        while True:
            try:
                line = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                line = "quit"

            if not line:
                continue

            parts = line.split(maxsplit=1)
            cmd = parts[0]
            payload = {}

            if cmd == "ping":
                pass
            elif cmd == "echo":
                payload = {"text": parts[1] if len(parts) > 1 else ""}
            elif cmd == "quit":
                pass
            else:
                print("Unknown command. Use: ping | echo <text> | quit")
                continue

            msg = {"op": cmd, "seq": seq, "payload": payload}
            seq += 1
            await send_msg(writer, msg)

            resp = await recv_msg(reader)
            if resp is None:
                print("Server closed the connection.")
                break

            print("< ", json.dumps(resp, ensure_ascii=False))

            if cmd == "quit":
                break

    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        print("Disconnected.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5050)
    args = ap.parse_args()
    asyncio.run(repl(args.host, args.port))
