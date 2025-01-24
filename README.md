### **1. Wprowadzenie**
Aplikacja służy do podpisywania dokumentów cyfrowych oraz weryfikacji ich podpisów przy użyciu kryptografii asymetrycznej. Kluczową rolę w aplikacji odgrywają klucze RSA, które są generowane, zapisywane do plików oraz odczytywane podczas pracy programu. Użytkownik może dynamicznie podawać hasło do zabezpieczenia klucza prywatnego.

---

### **2. Główne funkcjonalności aplikacji**

1. **Generowanie pary kluczy RSA**
2. **Zapisywanie kluczy do plików** (z szyfrowaniem klucza prywatnego)
3. **Wczytywanie kluczy z plików** (z odszyfrowaniem klucza prywatnego)
4. **Podpisywanie dokumentu** kluczem prywatnym
5. **Weryfikacja podpisu** kluczem publicznym

---

### **3. Działanie aplikacji krok po kroku**

#### **3.1 Generowanie pary kluczy**

1. Użytkownik wybiera opcję "Generate Key Pair".
2. Aplikacja wyświetla okno dialogowe do wpisania hasła, które będzie służyło do szyfrowania klucza prywatnego.
3. Po podaniu hasła aplikacja:
   - Generuje parę kluczy RSA za pomocą funkcji:
     ```python
     private_key = rsa.generate_private_key(
         public_exponent=65537,
         key_size=2048,
         backend=default_backend()
     )
     public_key = private_key.public_key()
     ```
     - **`public_exponent=65537`** – Standardowa wartość wykładnika publicznego używana w kryptografii RSA.
     - **`key_size=2048`** – Rozmiar klucza RSA w bitach, zapewniający wysoki poziom bezpieczeństwa.

4. Generowane klucze są zapisywane do plików w katalogu `keys/`:
   - Klucz prywatny jest szyfrowany za pomocą podanego hasła:
     ```python
     private_key.private_bytes(
         encoding=serialization.Encoding.PEM,
         format=serialization.PrivateFormat.PKCS8,
         encryption_algorithm=serialization.BestAvailableEncryption(password)
     )
     ```
     - **`serialization.BestAvailableEncryption(password)`** – Używa najlepszego dostępnego algorytmu szyfrowania klucza prywatnego przy użyciu hasła podanego przez użytkownika.

5. Klucz publiczny jest zapisywany w formacie PEM bez szyfrowania.
6. Aplikacja wyświetla komunikat o pomyślnym zapisaniu kluczy.

---

#### **3.2 Wczytywanie pary kluczy**

1. Użytkownik wybiera opcję "Load Key Pair".
2. Aplikacja wyświetla okno dialogowe do wpisania hasła, które zostało użyte do zaszyfrowania klucza prywatnego.
3. Po podaniu hasła aplikacja wczytuje klucze z plików:
   - Klucz prywatny jest odszyfrowywany za pomocą funkcji:
     ```python
     private_key = serialization.load_pem_private_key(
         priv_file.read(),
         password=password,
         backend=default_backend()
     )
     ```
   - Klucz publiczny jest wczytywany bez potrzeby podawania hasła.
4. Jeśli wczytanie kluczy zakończy się sukcesem, aplikacja wyświetla odpowiedni komunikat.

---

#### **3.3 Podpisywanie dokumentu**

1. Użytkownik wybiera opcję "Sign Document" i wskazuje plik, który chce podpisać.
2. Aplikacja wczytuje zawartość pliku i generuje podpis cyfrowy za pomocą klucza prywatnego:
   ```python
   signature = private_key.sign(
       document_data,
       padding.PSS(
           mgf=padding.MGF1(hashes.SHA256()),
           salt_length=padding.PSS.MAX_LENGTH
       ),
       hashes.SHA256()
   )
   ```
   - **`padding.PSS`** – Używa schematu wypełnienia PSS (Probabilistic Signature Scheme), który zapewnia wyższy poziom bezpieczeństwa niż starsze metody wypełnienia.
   - **`hashes.SHA256()`** – Algorytm skrótu SHA-256 jest używany do obliczenia skrótu wiadomości przed podpisaniem.

3. Podpis jest zapisywany w pliku z rozszerzeniem `.sig` w katalogu `signatures/`.
4. Aplikacja wyświetla komunikat o pomyślnym podpisaniu dokumentu.

---

#### **3.4 Weryfikacja podpisu**

1. Użytkownik wybiera opcję "Verify Signature" i wskazuje dokument oraz odpowiadający mu plik z podpisem.
2. Aplikacja wczytuje dokument i podpis, a następnie weryfikuje podpis za pomocą klucza publicznego:
   ```python
   public_key.verify(
       signature,
       document_data,
       padding.PSS(
           mgf=padding.MGF1(hashes.SHA256()),
           salt_length=padding.PSS.MAX_LENGTH
       ),
       hashes.SHA256()
   )
   ```
3. Jeśli podpis jest prawidłowy, aplikacja wyświetla komunikat o poprawności podpisu.
4. W przypadku błędnego podpisu lub innych problemów aplikacja wyświetla komunikat o niepowodzeniu weryfikacji.

---

### **4. Ważne funkcje kryptograficzne użyte w aplikacji**

1. **`rsa.generate_private_key`**
   - Generuje parę kluczy RSA (prywatny i publiczny).
   - Parametry:
     - `public_exponent=65537` – Wartość wykładnika publicznego.
     - `key_size=2048` – Długość klucza w bitach.

2. **`private_key.sign`**
   - Tworzy podpis cyfrowy dla danych za pomocą klucza prywatnego.
   - Używa schematu wypełnienia PSS oraz algorytmu skrótu SHA-256.

3. **`public_key.verify`**
   - Weryfikuje poprawność podpisu cyfrowego za pomocą klucza publicznego.
   - Używa tego samego schematu wypełnienia i algorytmu skrótu co podczas podpisywania.

4. **`serialization.BestAvailableEncryption`**
   - Służy do szyfrowania klucza prywatnego za pomocą hasła.
   - Zapewnia najlepszy dostępny poziom bezpieczeństwa szyfrowania.

5. **`serialization.load_pem_private_key`**
   - Odczytuje i odszyfrowuje klucz prywatny z pliku PEM przy użyciu podanego hasła.

6. **`serialization.load_pem_public_key`**
   - Odczytuje klucz publiczny z pliku PEM.

---

### **5. Podsumowanie**
Aplikacja zapewnia bezpieczeństwo dokumentów poprzez wykorzystanie kryptografii asymetrycznej oraz zaawansowanych metod podpisywania i weryfikacji. Szyfrowanie klucza prywatnego za pomocą hasła gwarantuje, że tylko osoba znająca hasło może podpisać dokumenty.
