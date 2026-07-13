import asyncio
import json
import base64
import rsa
import websockets


async def main():
    server_url = input("Relay server WebSocket URL (e.g. wss://your-app.onrender.com): ").strip()
    my_username = input("Apna username choose karo: ").strip()
    target_username = input("Kisse chat karni hai (unka username): ").strip()

    public_key, private_key = rsa.newkeys(2048)
    partner_public_key = None
    partner_key_ready = asyncio.Event()   # humein partner ki public key mil gayi
    own_key_acked = asyncio.Event()       # partner ne confirm kar diya ki usse humari key mil gayi

    async with websockets.connect(server_url) as ws:
        await ws.send(json.dumps({"type": "register", "username": my_username}))

        async def send_payload(kind, payload_bytes):
            encoded = base64.b64encode(payload_bytes).decode()
            await ws.send(json.dumps({
                "type": "msg",
                "target": target_username,
                "kind": kind,
                "payload": encoded
            }))

        async def receiver():
            nonlocal partner_public_key
            async for message in ws:
                try:
                    data = json.loads(message)
                except Exception:
                    continue  # malformed JSON - ignore, crash mat karo

                try:
                    if data.get("type") == "error":
                        print(f"\n{data['message']}")
                        continue

                    if data.get("type") != "from":
                        continue

                    kind = data.get("kind")
                    raw = base64.b64decode(data["payload"])

                    if kind == "pubkey":
                        try:
                            partner_public_key = rsa.PublicKey.load_pkcs1(raw)
                            if not partner_key_ready.is_set():
                                print(f"\n[{data['sender']} ki public key mil gayi. Chat shuru kar sakte ho.]")
                            partner_key_ready.set()
                        except Exception:
                            print(f"\n[{data['sender']} se aayi key parse nahi ho payi, ignore kar rahe hain]")
                            continue
                        # Partner ko batao ki key mil gayi, taaki wo apna retry band kare
                        await send_payload("pubkey_ack", b"ack")

                    elif kind == "pubkey_ack":
                        own_key_acked.set()

                    elif kind == "chat":
                        try:
                            decrypted = rsa.decrypt(raw, private_key).decode()
                            print(f"\n{data['sender']}: {decrypted}\nYou: ", end="", flush=True)
                        except Exception:
                            print(f"\n[Message decrypt nahi ho paaya]")

                except Exception:
                    # Kuch bhi anexpected ho jaaye, poora receiver crash nahi hona chahiye
                    print("\n[Ek message process karte waqt error aaya, ignore kar rahe hain]")

        async def send_own_key_until_acked():
            while not own_key_acked.is_set():
                await send_payload("pubkey", public_key.save_pkcs1("PEM"))
                try:
                    await asyncio.wait_for(own_key_acked.wait(), timeout=5)
                except asyncio.TimeoutError:
                    pass  # 5 second ho gaye, ack nahi mila - dubara bhejo

        receiver_task = asyncio.create_task(receiver())
        retry_task = asyncio.create_task(send_own_key_until_acked())

        print("Apni public key bhej rahe hain, partner ki public key ka wait kar rahe hain...")
        await partner_key_ready.wait()

        loop = asyncio.get_event_loop()
        while True:
            msg = await loop.run_in_executor(None, input, "You: ")
            if msg.lower() == "exit":
                break
            try:
                encrypted = rsa.encrypt(msg.encode(), partner_public_key)
                await send_payload("chat", encrypted)
            except Exception as e:
                print(f"Error: {e} (message bahut lamba ho sakta hai, ~245 bytes limit hai)")

        receiver_task.cancel()
        retry_task.cancel()


if __name__ == "__main__":
    asyncio.run(main())
