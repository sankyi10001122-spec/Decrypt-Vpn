# Config Vault

ကိုယ့် config ဖိုင်များကို browser ထဲမှာသာ encrypt/decrypt လုပ်ရန် static website starter ဖြစ်သည်။ Backend၊ database၊ API key မလိုပါ။ ဖိုင်နှင့် password ကို server သို့ မပို့ပါ။

## လိုအပ်ချက်

Modern browser နှင့် HTTPS လိုအပ်သည်။ Web Crypto API ကြောင့် `file://` ဖြင့် တိုက်ရိုက်ဖွင့်ရာတွင် browser အချို့က ပိတ်နိုင်သည်။ Local စမ်းသပ်ရန် project folder ထဲမှ အောက်ပါအတိုင်း run ပါ။

```bash
python3 -m http.server 8000
```

ပြီးလျှင် `http://localhost:8000` သို့ ဝင်ပါ။ Live server ပေါ်တွင် HTTPS ဖြင့် host လုပ်ပါ။ Apache/Nginx/shared hosting တို့တွင် `index.html`, `styles.css`, `app.js` ကို web root သို့ copy လုပ်ရုံဖြင့်ရသည်။ `index.html` ကို default page အဖြစ် serve လုပ်ပါ။

## Encryption format

ဒီ project သည် өөрийн `CVLT1` format (`.enc`) ашигладаг тул cryptfile.online ၏ `.enc` ဖိုင်များနှင့် အပြန်အလှန် compatible မဟုတ်ပါ။ အခြား app ၏ `.ehi`, `.hc`, `.npvt`, `.tnl`, `.dark` ဖိုင်များကို ဖြည်ရန် tool မဟုတ်ပါ။ ဒီ format မှာ magic bytes, JSON metadata, salt, IV နှင့် AES-GCM ciphertext ပါသည်။ PBKDF2-HMAC-SHA-256 ကို random 16-byte salt နှင့် 600,000 iterations ဖြင့်သုံးပြီး AES-256-GCM key ရယူသည်။ Header အပြည့်အစုံကို GCM additional authenticated data အဖြစ်သုံးသည်။

ဖိုင်အများဆုံးအရွယ်အစားကို 100 MiB သတ်မှတ်ထားသည်။ Browser မှာဖိုင်ကို memory ထဲသို့ ဖတ်သောကြောင့် ဖုန်းအဟောင်း/မှတ်ဉာဏ်နည်းသောစက်များတွင် သေးငယ်သောဖိုင်ကိုသာ သုံးပါ။ Filename နဲ့ MIME type က encrypted file header ထဲတွင် plaintext အဖြစ် ရှိနေသည်။ Filename မှ အရေးကြီးသောအချက်အလက် မပေါက်ကြားစေရန် အမည်ပြောင်းပြီးမှ encrypt လုပ်ပါ။ Password ပျောက်လျှင် recovery မရှိပါ။

## Security နှင့် ဖြန့်ချိမှု

Crypto ကို browser ၏ Web Crypto API ဖြင့် ဆောင်ရွက်သည်။ Production မှာ HTTPS ကို မဖြစ်မနေသုံးပါ။ Content Security Policy နှင့် security headers ကို web server တွင် ထည့်ပါ။ Source code ကို ပြင်ဆင်ပြီး မထုတ်ဝေပါနှင့်၊ third-party analytics/scripts ထည့်မည်ဆိုလျှင် ဖိုင်ဒေတာမရောက်ကြောင်း စစ်ဆေးပါ။ ဒီ implementation က file upload endpoint မပါဝင်ပါ။

AES-GCM/PBKDF2 သည် စံသတ်မှတ်ထားသော cryptographic နည်းလမ်းများဖြစ်သော်လည်း website host လုပ်သူသည် browser သို့ပို့သော code ကို ပြောင်းလဲနိုင်သည်။ ထို့ကြောင့် hosting ပိုင်ရှင်အပေါ် မယုံကြည်နိုင်ပါက လျှို့ဝှက်ဖိုင်များကို မတင်ပါနှင့်။ ကိုယ်ယုံကြည်သော HTTPS domain ပေါ်တွင်သာ အသုံးပြုပါ။

## Files

- `index.html` — интерфейс
- `styles.css` — харагдах байдал
- `app.js` — file handling ба Web Crypto код
