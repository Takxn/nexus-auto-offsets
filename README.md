# NEXUS+ AUTO-OFFSET GENERATOR v3.1

Vollautomatische Offsets.h-Generierung für Rust (IL2CPP) + integrierter Offset-Tester.  
Läuft in **IDA Pro 9.x** und kommuniziert mit dem **NullKD** Kernel-Treiber zum Live-Testen.

---

## Übersicht: Was du brauchst

| Komponente | Zweck |
|------------|--------|
| **IDA Pro 9.x** | Disassembler, läuft das NEXUS+ Plugin |
| **Il2CppDumper** | Erzeugt `ida_py3.py` aus GameAssembly.dll + Metadaten |
| **GameAssembly.dll** | Aus dem Rust-Installationsordner |
| **global-metadata.dat** | Aus dem Rust-Installationsordner |
| **NullKD Treiber** | Kernel-Treiber zum Lesen/Schreiben von Rust-Speicher |
| **Rust (Spiel)** | Muss laufen, um Offsets live zu testen |

---

## Schritt 1: Il2CppDumper und ida_py3.py

### 1.1 Il2CppDumper herunterladen

1. Öffne: **https://github.com/Perfare/Il2CppDumper/releases**
2. Lade **Il2CppDumper-net6-win.zip** herunter.
3. Entpacke z.B. nach `C:\Tools\Il2CppDumper\`.

### 1.2 Rust-Dateien holen

Diese Dateien liegen in deiner **Rust-Installation** (Steam):

```
C:\Program Files (x86)\Steam\steamapps\common\Rust\
├── GameAssembly.dll
└── Rust_Data\il2cpp_data\Metadata\
    └── global-metadata.dat
```

- **GameAssembly.dll** → aus dem Hauptordner `Rust\`
- **global-metadata.dat** → aus `Rust\Rust_Data\il2cpp_data\Metadata\`

Kopiere beide z.B. nach `C:\Reversing\` (oder einen anderen Ordner).

### 1.3 Il2CppDumper ausführen

1. **Il2CppDumper.exe** starten (im entpackten Il2CppDumper-Ordner).
2. **Erste Datei:** `GameAssembly.dll` auswählen (z.B. aus `C:\Reversing\`).
3. **Zweite Datei:** `global-metadata.dat` auswählen.
4. **Output-Ordner:** z.B. `C:\Reversing\output\` wählen.
5. Warten, bis die Verarbeitung fertig ist.

Im Output-Ordner liegen u.a.:

- **ida_py3.py** → Dieses Skript lädst du später in IDA (für Python 3).
- **dump.cs** → Optional: lesbare C#-Klassen-Übersicht.

**Merke dir den Pfad zu ida_py3.py** (z.B. `C:\Reversing\output\ida_py3.py`).

---

## Schritt 2: IDA Pro einrichten

### 2.1 Python 3 in IDA aktivieren (einmalig)

1. Im **IDA 9.3 Pro**-Ordner **idapyswitch.exe** starten.
2. Eine **Python-3-Installation** auswählen (z.B. Nummer **0** und Enter).
3. IDA danach **komplett schließen** und wieder starten.

### 2.2 NEXUS+ Plugin in IDA einbinden (einmalig)

1. Öffne den Ordner deiner **IDA Pro**-Installation (z.B. `C:\Program Files\IDA Pro 9.3\` oder `...\IDA 9.3 Pro\`).
2. Gehe in den Unterordner **`plugins`**.
3. Kopiere **NEXUS+_AUTO-OFFSET_GENERATOR_v3.1.py** aus diesem Repository in genau diesen Ordner.

   **Zielpfad (Beispiel):**
   ```
   <IDA-Installation>\plugins\NEXUS+_AUTO-OFFSET_GENERATOR_v3.1.py
   ```
   z.B. `C:\Program Files\IDA Pro 9.3\plugins\NEXUS+_AUTO-OFFSET_GENERATOR_v3.1.py`

4. IDA **neu starten** (komplett beenden und wieder öffnen).
5. Prüfen: **Edit** → **Plugins** → Eintrag **„NEXUS+ Offset Generator“** sollte erscheinen.

---

## Schritt 3: Nach jedem Rust-Update – Offsets generieren

### 3.1 Neue Rust-Dateien besorgen

Nach einem Rust-Update wieder aus dem Spielordner kopieren:

- **GameAssembly.dll**
- **global-metadata.dat**

(z.B. wieder nach `C:\Reversing\`).

### 3.2 Il2CppDumper erneut ausführen

1. **Il2CppDumper.exe** starten.
2. Neue **GameAssembly.dll** auswählen.
3. Neue **global-metadata.dat** auswählen.
4. Gleichen oder neuen **Output-Ordner** wählen (dort liegt wieder **ida_py3.py**).

### 3.3 GameAssembly.dll in IDA laden

1. **IDA Pro** starten.
2. **File** → **Open** → **GameAssembly.dll** auswählen (die neue aus Schritt 3.1).
3. Dialoge mit **OK** bestätigen.
4. Warten, bis die **Analyse fertig** ist (Fortschrittsbalken unten).

### 3.4 Metadaten in IDA laden (ida_py3.py)

1. In IDA: **File** → **Script file...**
2. Unten bei **„Files of type“** auf **„All files (*.*)“** oder **„Python files (*.py)“** stellen.
3. **ida_py3.py** auswählen (z.B. aus `C:\Reversing\output\ida_py3.py`).
4. **Öffnen** klicken.
5. **5–20 Minuten** warten – IDA benennt tausende Funktionen um.

### 3.5 NEXUS+ Plugin ausführen

1. **Edit** → **Plugins** → **NEXUS+ Offset Generator** klicken.
2. Das Skript läuft durch (Phasen 1–5).
3. Am Ende erscheint ein Dialog: **„Offset Tester jetzt öffnen?“**
   - **Ja** → Tester-Fenster öffnet sich (zum Testen mit Treiber + Rust, siehe Schritt 5).
   - **Nein** → Nur Offsets.h wurde erzeugt.

**Offsets.h** liegt danach auf dem **Desktop**.

### 3.6 STypeInfo0–4 prüfen (optional)

In der generierten **Offsets.h** steht ein Hinweis:

```c
// TODO: STypeInfo0-4 — unknown classes, verify manually after each update
```

Diese fünf Werte solltest du nach dem Update in IDA prüfen und ggf. manuell anpassen.

---

## Schritt 4: NullKD Treiber laden

Der Treiber wird benötigt, um **live** aus dem Rust-Prozess zu lesen (Offset-Tester).

### 4.1 Treiber bauen (falls noch nicht geschehen)

- Projekt: **Rust-Offset-Tester\NullKD**
- In Visual Studio öffnen und für **x64** bauen (Release).
- Ergebnis: **NullkD.sys** (oder die gebaute Treiber-Datei).

### 4.2 Treiber laden (als Administrator)

1. **DigiMapper.exe** als **Administrator** starten (Rechtsklick → „Als Administrator ausführen“).
2. In DigiMapper den Treiber **NullkD.sys** auswählen und laden.
3. Prüfen: DigiMapper zeigt an, ob der Treiber erfolgreich geladen wurde.

**Hinweis Antivirus/Windows:** **DigiMapper.exe** und **NullkD.sys** können von Antivirenprogrammen oder Windows Defender als verdächtig erkannt und blockiert bzw. gelöscht werden (False Positive). In dem Fall: Ausnahme/Whitelist für den Ordner anlegen oder temporär deaktivieren – nur auf eigenes Risiko.

**Wichtig:** Treiber nur auf eigenes Risiko und in Übereinstimmung mit den Nutzungsbedingungen von Rust/EAC nutzen.

---

## Schritt 5: Offsets live testen

### 5.1 Was muss laufen?

- **IDA Pro** mit **GameAssembly.dll** geladen (und optional ida_py3.py bereits ausgeführt).
- **NullKD Treiber** geladen (Schritt 4).
- **Rust** (RustClient.exe) **gestartet** – am besten im Hauptmenü oder in einer Welt.

### 5.2 Tester öffnen

**Variante A – direkt nach der Generierung**

- Beim Dialog **„Offset Tester jetzt öffnen?“** → **Ja** klicken.

**Variante B – später**

- **Edit** → **Plugins** → **NEXUS+ Offset Generator** erneut ausführen.
- Am Ende wieder **„Offset Tester jetzt öffnen?“** → **Ja**.

### 5.3 Im Tester-Fenster

1. **Neu verbinden** klicken → Treiber, Rust-PID und **GameAssembly.dll**-Basis werden ermittelt.
2. **Filter** nutzen (z.B. `AdminConvar`, `BasePlayer`), um nur bestimmte Offsets zu sehen.
3. **Lesen** bei einer Zeile klicken → Wert wird aus dem laufenden Rust-Prozess gelesen.
4. **Alle lesen** → alle sichtbaren Offsets nacheinander lesen.
5. **In IDA springen** → Zeile auswählen, klicken → IDA springt zur zugehörigen Adresse.

Wenn **Treiber: ✓ OK**, **PID** angezeigt und **Base** (GameAssembly) gesetzt ist, sind die gelesenen Werte live aus dem Spiel.

---

## Kurz-Checkliste pro Rust-Update

| # | Aktion | Erledigt |
|---|--------|----------|
| 1 | GameAssembly.dll + global-metadata.dat aus Rust-Ordner kopieren | ☐ |
| 2 | Il2CppDumper ausführen → ida_py3.py erzeugen | ☐ |
| 3 | IDA starten, GameAssembly.dll laden, Analyse abwarten | ☐ |
| 4 | File → Script file → ida_py3.py ausführen, warten | ☐ |
| 5 | Edit → Plugins → NEXUS+ Offset Generator ausführen | ☐ |
| 6 | Offsets.h vom Desktop ins Cheat-Projekt kopieren | ☐ |
| 7 | (Optional) STypeInfo0–4 in Offsets.h manuell prüfen | ☐ |
| 8 | (Zum Testen) NullKD laden, Rust starten, Tester öffnen | ☐ |

---

## Dateien und Ordner (Überblick)

```
NEXUS+ AUTO-OFFSET GENERATOR v3.1\
├── README.md                          ← Diese Anleitung
├── NEXUS+_AUTO-OFFSET_GENERATOR_v3.1.py
├── offsets.txt                        ← Referenz-Offsets (wird vom Skript nicht überschrieben)
├── IDA 9.3 Pro\
│   └── plugins\
│       └── NEXUS+_AUTO-OFFSET_GENERATOR_v3.1.py   ← Kopie für Edit → Plugins
└── Rust-Offset-Tester\
    └── NullKD\                        ← Treiber-Projekt
```

**Il2CppDumper-Output** (z.B. `C:\Reversing\output\`):

- **ida_py3.py** → in IDA laden
- dump.cs, script.json, etc. (optional)

**Nach dem Lauf des Plugins:**

- **Desktop\Offsets.h** → in dein Cheat-Projekt kopieren

---

## Häufige Probleme

| Problem | Lösung |
|--------|--------|
| „Python 3 is not configured“ | **idapyswitch.exe** ausführen, Python 3 wählen, IDA neu starten. |
| Plugin erscheint nicht unter Plugins | IDA neu starten. Prüfen, ob die .py-Datei im Ordner **plugins** liegt. |
| „BaseNetworkable_c not found“ | GameAssembly.dll in IDA laden (nicht nur Il2CppDumper). |
| Alles Fallback ([-]) | ida_py3.py in IDA ausgeführt? Dann sind Namen da; Plugin erneut ausführen. |
| Tester: „Treiber: ✗“ | NullKD-Treiber laden (Schritt 4), danach „Neu verbinden“. |
| Tester: „Rust nicht gefunden“ | Rust (RustClient.exe) starten, dann „Neu verbinden“. |
| DigiMapper/NullkD wird blockiert oder gelöscht | Antivirus/Windows erkennt Treiber-Loader oft als False Positive. Ausnahme für den Ordner anlegen oder Datei als vertrauenswürdig markieren. |

---

## Rechtlicher Hinweis

Dieses Tool dient ausschließlich zu Bildungs- und Forschungszwecken. Die Nutzung von Cheats und Kernel-Treibern gegen Online-Spiele verstößt in der Regel gegen die Nutzungsbedingungen und kann zu Banns und rechtlichen Konsequenzen führen.
