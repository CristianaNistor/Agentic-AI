import os
from dotenv import load_dotenv
from google import genai

# 1. Încarcă variabilele definite în fișierul .env
load_dotenv()

# 2. Verifică existența cheii înainte de apelul de rețea
api_key = os.getenv("GEMINI_API_KEY")
assert api_key, "EROARE: GEMINI_API_KEY nu a fost găsită. Verifică fișierul .env!"

# 3. Clientul citește automat GEMINI_API_KEY din mediul procesului
client = genai.Client()

# 4. Apel minim de verificare către modelul din laborator
response = client.models.generate_content(
    model="gemini-3.5-flash-lite",
    contents="Reply with the exact phrase: 'Telemetry online.'"
)

print("\n--- Răspuns de la model ---")
print(response.text.strip())