from openai import OpenAI

def main():
    # Configure client to point to local Ollama instance
    client = OpenAI(
        base_url="http://localhost:11434/v1",
        api_key="ollama"  # Required by SDK format; ignored by Ollama
    )

    messages = [
        {
            "role": "system",
            "content": "You are a helpful and concise academic mentor. Provide direct and accurate answers."
        }
    ]

    print("=== Terminal Chat Loop Started ===")
    print("Type 'exit' or 'quit' to end the session.\n")

    # Bucla interactivă
    while True:
        try:
            # Cerința 3: Citire input de la utilizator (stdin)
            user_input = input("User: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting session...")
            break

        # Ignorăm dacă utilizatorul apasă Enter fără text
        if not user_input:
            continue

        # Cerința 8: Suport pentru comandă de ieșire
        if user_input.lower() in ("exit", "quit"):
            print("Exiting session. Goodbye!")
            break

        # Cerința 4: Adăugarea input-ului utilizatorului în istoric cu rolul 'user'
        messages.append({
            "role": "user",
            "content": user_input
        })

        try:
            # Cerința 5: Trimiterea întregului istoric către model via API
            # Folosim temperature=0.0 pentru determinism și precizie
            response = client.chat.completions.create(
                model="qwen2.5:1.5b",
                temperature=0.0,
                messages=messages
            )

            assistant_reply = response.choices[0].message.content

            # Cerința 6: Afișarea răspunsului generat de model
            print(f"\nAssistant: {assistant_reply}\n")

            # Cerința 7: CRUCIAL - Adăugarea răspunsului asistentului înapoi în istoric cu rolul 'assistant'
            messages.append({
                "role": "assistant",
                "content": assistant_reply
            })

        except Exception as e:
            print(f"Error calling model: {e}")
            # Dacă cererea a eșuat, eliminăm ultimul mesaj introdus pentru a păstra istoricul curat
            messages.pop()

if __name__ == "__main__":
    main()