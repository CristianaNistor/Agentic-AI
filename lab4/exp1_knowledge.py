"""Lab 4 - Experiment 1: what does the model actually know? (given, nothing to complete)"""
import sys

from llm import QuotaExhausted, ask

PROBES = [
    "What is today's date?",
    "What is the cheapest flight from Iasi to Rome next Tuesday, and how much does it cost?",
    "Which concerts are on in Rome in the second week of May 2027?",
    "Is the Borghese Gallery in Rome open on Mondays, and how do you get tickets?",
]

if __name__ == "__main__":
    for q in PROBES:
        try:
            r = ask(q)
        except QuotaExhausted as e:  # every next call would fail the same way: stop
            sys.exit(f"\n[stopped] {e}")
        except TimeoutError as e:  # one slow answer: report it and go on
            print(f"\n### {q}\n[timeout] {e}")
            continue
        print(f"\n### {q}\n{r.text.strip()[:600]}")

# Which questions does the model refuse, and which does it answer confidently?
# Refuza sa raspunda la intrebarile care necesita informatii actualizate sau care nu sunt in baza sa de date.
# Raspunde cu incredere la intrebarea legata de programul galeriei Borghese, deoarece aceasta informatie este mai stabila si mai usor de accesat.

# One answer comes from memory with no source. Is it still true today? How would your agent find out?
# Raspunsul despre programul galeriei Borghese poate fi inca valabil, dar este recomandata verificarea site-ului oficial. Un agent real ar trebui
# sa verifice site-ul oficial al galeriei sau sa contacteze direct institutia pentru a obtine informatii actualizate.

# What does the model say about its own knowledge, and what year does it think it is? (Remember this for Experiment 5.)
# Modelul recunoaste ca nu are acces la informatii in timp real si ca datele sale sunt limitate la cunostintele acumulate pana la un anumit punct. 
# Nu poate determina cu exactitate anul curent fara un indiciu extern.