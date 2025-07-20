# 🛡️ MexScan

**MexScan** adalah alat _All-in-One Web Exploitation & Vulnerability Scanner_ yang dirancang khusus untuk para bug hunter, peneliti keamanan, dan profesional pentest. Alat ini mampu melakukan deteksi dan eksploitasi otomatis terhadap berbagai jenis kerentanan umum seperti **XSS**, **SQL Injection**, **Remote Code Execution**, dan **XML External Entity (XXE)** mulai dari _root domain_.

---

## 🚀 Fitur Unggulan

- 🔍 Crawling otomatis dengan batas maksimum endpoint
- 📌 Deteksi XSS, SQLi, RCE, dan XXE
- 🧠 Payload injection otomatis
- 🧪 Eksploitasi awal untuk konfirmasi kerentanan
- 🧵 Multithreaded scanning (dapat dikembangkan lebih lanjut)
- 🔒 Dukungan proxy & header kustom
- ⚡ Mudah dioperasikan dari command-line

---

## 📦 Instalasi
git clone https://github.com/username/mexscan.git
cd mexscan
pip install -r requirements.txt
python3 mexscan.py http://target.com

#GUI_RUN 
python3 mexscan_gui.py 

#validation ssl no detection warning 
pip install urllib3   >>> install

