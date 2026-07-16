# 🩸 Bloodyomain — Active Directory Enumeration & Attack Path Visualization

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License MIT">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/AD-Audit-red.svg" alt="AD Audit">
</p>

<p align="center"><b>TR</b> | <a href="#-bloodyomain--active-directory-enumeration--attack-path-visualization-1">EN</a></p>

---

## 🇹🇷 Türkçe

### Genel Bakış

**Bloodyomain**, Active Directory ortamlarının kapsamlı güvenlik denetimi için geliştirilmiş, saldırı yolu görselleştirme odaklı bir araçtır. LDAP ve SMB protokolleri üzerinden etki alanını derinlemesine tarar, 25'ten fazla saldırı zincirini otomatik olarak analiz eder ve etkileşimli bir HTML raporu sunar.

Pentester'lar, red team operatörleri ve AD güvenlik denetçileri için tasarlanmıştır.

### Özellikler

#### 🔍 Keşif & Enumeration
| Kategori | Detay |
|----------|-------|
| **Domain Bilgisi** | Functional level, machine account quota, domain SID, controller listesi |
| **Kullanıcılar** | Tüm kullanıcı atributları, adminCount, SPN, ASREP, enabled/disabled durumu |
| **Gruplar** | İç içe grup çözümleme (nested group resolution), adminCount, Protected Users |
| **Bilgisayarlar** | İşletim sistemi, domain controller, delegation türleri, LAPS, RDP durumu |
| **OU & GPO** | Organizational Unit yapısı, GPO linkleri |
| **Trust** | Cross-forest trust ilişkileri ve yönü |
| **Tombstoned** | Silinmiş fakat tombstone süresi dolmamış objeler |
| **SPN / ASREP** | Kerberoastable ve ASREPRoastable hesaplar |
| **ADCS** | Sertifika otoriteleri, şablonları, ESC1-ESC8 sınıflandırması |
| **ADFS** | Federation servis yapılandırması |
| **LAPS** | LAPS okuyucu grupları ve yetkili hesaplar |
| **Schema Admins / Enterprise Admins** | Yüksek ayrıcalıklı grup üyelikleri |
| **Service Accounts** | SPN bazlı servis hesabı haritası |


<details>
<summary><b>📋 Detaylı Enumeration Listesi (tıklayarak genişlet)</b></summary>

| # | Metod | Açıklama |
|---|-------|----------|
| 1 | `_enum_domain` | Domain functional level, machine quota, DC list |
| 2 | `_enum_users` | Kullanıcı atributları: UAC, lastLogon, pwdLastSet, memberOf, adminCount |
| 3 | `_enum_tombstoned` | Silinmiş objeler (tombstone) |
| 4 | `_enum_groups` | Grup üyelikleri ve adminCount |
| 5 | `_enum_protected_users` | Protected Users grubu üyeleri |
| 6 | `_resolve_nested_groups` | İç içe grup çözümleme |
| 7 | `_check_ldap_security` | LDAP signing ve channel binding durumu |
| 8 | `_enum_computers` | Bilgisayarlar: OS, SP, delegation, LAPS, RDP |
| 9 | `_enum_ous_gpos` | OU ağacı ve GPO linkleri |
| 10 | `_enum_admins` | Domain/Enterprise Admins + Administrators üyeleri |
| 11 | `_report_spns` | Kerberoastable hesaplar |
| 12 | `_report_asrep` | ASREPRoastable hesaplar |
| 13 | `_check_nopac` | NoPAC (CVE-2021-42278/42287) risk değerlendirmesi |
| 14 | `_enum_trusts` | Cross-forest trust |
| 15 | `_enum_dacls` | Kritik objeler üzerinde DACL analizi |
| 16 | `_enum_adcs` | ADCS ESC1-ESC8 tespiti |
| 17 | `_enum_adfs` | ADFS sunucu ve yapılandırma |
| 18 | `_enum_laps_readers` | LAPS okuyucu yetkileri |
| 19 | `_enum_schema_enterprise_admins` | Schema/Enterprise Admin üyelikleri |
| 20 | `_map_service_accounts` | Servis hesabı → SPN eşleştirme |
| 21 | `_check_coercion_targets` | PrinterBug / PetitPotam coercion hedefleri |
| 22 | `_check_ntlm_relay_risk` | SMB signing kapalı DC'ler → NTLM Relay riski |
| 23 | `_build_delegation_matrix` | Delegasyon matrisi |
| 24 | `_enum_shadow_creds` | msDS-KeyCredentialLink (Shadow Credentials) |
| 25 | `_enum_dcsync_rights` | DCSync yetkileri (Replicating Changes) |
| 26 | `_enum_fgpp` | Fine-Grained Password Policy |
| 27 | `_enum_gpo_write_perms` | GPO yazma izinleri |
| 28 | `_enum_adminsdholder` | AdminSDHolder ACL analizi |
| 29 | `_enum_sensitive_files` | SYSVOL hassas dosya taraması |
| 30 | `_vuln_scan` | Güvenlik açığı taraması |
| 31 | `_enum_exchange_perms` | Exchange Windows Permissions → DCSync |
| 32 | `_password_spray` | Parola spreyi |
| 33 | `_build_remediation` | MITRE ATT&CK eşlemeli düzeltme önerileri |
| 34 | `_scan_description_passwords` | Kullanıcı description alanında parola taraması |
| 35 | `_enum_gpo_contents` | SYSVOL GPO crawler — cpassword decrypt + script credential |
| 36 | `_validate_credentials` | Bulunan tüm credential'ları LDAP/SMB/WinRM üzerinden test et |
| 37 | `_enum_ou_dacls` | OU konteynerlerinde ACL analizi |
| 38 | `_enum_mssql` | MSSQL sunucu ve servis hesabı enumerasyonu (SPN tabanlı) |
| 39 | `_enum_sccm` | SCCM/MECM site sunucusu ve NAA hesabı enumerasyonu |
| 40 | `_read_laps_passwords` | LAPS şifrelerini LDAP üzerinden okuma |

</details>

#### 🔗 SMB Tarama
| Özellik | Açıklama |
|----------|----------|
| **Session Enumeration** | Tüm hostlarda aktif SMB oturumları |
| **LoggedOn Kullanıcılar** | Hostlarda oturum açmış kullanıcılar |
| **Local Admin** | Her hostta local administrator grubu üyeleri |
| **Share Enumeration** | Paylaşımlı klasörler ve izinler |
| **RDP Tarama** | RDP (3389) açık hostlar ve Remote Desktop Users |
| **SMB Signing** | SMB imzalama durumu ( relay saldırıları için) |
| **Spooler** | Print Spooler servis durumu |
| **ZeroLogon** | ZeroLogon (CVE-2020-1472) açıklık kontrolü |
| **WinRM** | WinRM (5985) erişilebilirliği |

#### ⛓️ Saldırı Zinciri Analizi (36+ Zincir)

Bloodyomain, topladığı verileri analiz ederek aşağıdaki saldırı zincirlerini otomatik olarak oluşturur ve `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` olarak sınıflandırır:

| # | Saldırı Zinciri | Açıklama |
|---|-----------------|----------|
| 1 | **Privileged Session** | DA oturumu olan hostlara erişim |
| 2 | **Local Admin → DA** | Local admin olunan hostta DA oturumu |
| 3 | **RDP → DA Session** | RDP + DA oturumu olan host |
| 4 | **Kerberoast** | Yüksek ayrıcalıklı hesapta SPN |
| 5 | **ASREP Roast** | Ön kimlik doğrulama gerektirmeyen hesaplar |
| 6 | **Unconstrained Delegation** | Kısıtlamasız delegasyon riskleri |
| 7 | **Constrained Delegation** | Kısıtlı delegasyon riskleri |
| 8 | **RBCD** | Resource-Based Constrained Delegation |
| 9 | **ACL Chains** | Kritik ACL ilişkileri (GenericAll, WriteOwner, WriteDacl) |
| 10 | **Password Policy** | Zayıf parola politikası riskleri |
| 11 | **Stale Accounts** | Eski/dokunulmamış hesaplar |
| 12 | **Nested Group** | Aşırı derin nested grup riskleri |
| 13 | **Machine Quota** | Varsayılan makine kotası riski |
| 14 | **ADCS (ESC1-8)** | Sertifika servisi saldırı yolları |
| 15 | **Password Not Req** | Parola gerektirmeyen hesaplar |
| 16 | **AdminCount** | adminCount=1 olan kritik hesaplar |
| 17 | **Pwd Never Expires** | Parolası süresiz hesaplar |
| 18 | **Shadow Credentials** | msDS-KeyCredentialLink riskleri |
| 19 | **GPO Write** | GPO yazma yetkisi olan hesaplar |
| 20 | **AdminSDHolder** | AdminSDHolder ACL kötüye kullanımı |
| 21 | **Silver Ticket** | Silver ticket için uygun koşullar |
| 22 | **S4U** | S4U2Self/S4U2Proxy kötüye kullanımı |
| 23 | **KRBRelay** | KRBRelay için uygun sunucular |
| 24 | **PrintNightmare** | Print Spooler + yazma yetkisi |
| 25 | **ZeroLogon → DCSync** | ZeroLogon ile domain admin |
| 26 | **Exchange → DCSync** | Exchange Windows Permissions ile DCSync |
| 27 | **Delegation-Aware** | Delegasyon-tabanlı birleşik zincirler |
| 28 | **Description Credential** | Kullanıcı description alanında bulunan parolalar |
| 29 | **GPO Credential** | GPO/SYSVOL içinde bulunan credential'lar |
| 30 | **Validated Credential** | Test edilip doğrulanmış credential'lar |
| 31 | **OU ACL Abuse** | OU seviyesinde GenericAll/WriteOwner tespiti |
| 32 | **DNSAdmins Abuse** | DNSAdmins → DC SYSTEM (dns.exe DLL injection) |
| 33 | **Cross-Forest SID Abuse** | SID filtering kapalı trust → cross-forest admin |
| 34 | **MSSQL Chain** | MSSQL servis hesabı → Kerberoast → DA zinciri |
| 35 | **SCCM Chain** | SCCM NAA hesabı → tüm client'lara local admin |
| 36 | **LAPS Chain** | LAPS şifresi okunabilen bilgisayarlar + DA session |

#### 🛡️ DACL Analizörü
- Özel DACL/ACE parser (security descriptor kontrolü)
- Kritik yetkilerin tespiti: `GenericAll`, `WriteOwner`, `WriteDacl`, `WriteProperty`, `ExtendedRight`, `AddMember`, `ForceChangePassword`
- Domain Admins, Enterprise Admins, AdminSDHolder gibi kritik objelere odaklanma

#### 🕵️ Credential Hunting
| Özellik | Açıklama |
|----------|----------|
| **Description Scanner** | Kullanıcı description alanlarında 12+ regex pattern ile parola taraması (Türkçe keyword destekli) |
| **GPO/SYSVOL Crawler** | Groups.xml/Services.xml içindeki `cpassword` AES decrypt + .bat/.ps1/.vbs hardcoded credential |
| **Credential Validator** | Bulunan tüm credential'ları LDAP bind ile test etme + WinRM/SMB doğrulama |

#### 🔬 Gelişmiş Denetim
| Özellik | Açıklama |
|----------|----------|
| **DCSync Rights** | Domain controller'da Replicating Changes yetkileri |
| **FGPP** | Fine-Grained Password Policy analizi |
| **Shadow Credentials** | msDS-KeyCredentialLink atributu taraması |
| **AdminSDHolder** | AdminSDHolder objesi üzerindeki ACL'ler |
| **GPO Write Perms** | GPO'lar üzerinde yazma izinleri |
| **OU Container ACLs** | OU seviyesinde GenericAll/WriteOwner/WriteDACL analizi |
| **Sensitive Files** | SYSVOL üzerinde şifre/secret içeren dosyalar |
| **Coercion Targets** | PrinterBug / PetitPotam için uygun hostlar |
| **PrinterNightmare Deep** | Spooler + PointAndPrint + RpcAuthnLevel detaylı analiz |
| **NTLM Relay** | SMB signing kapalı DC'ler → NTLM Relay riski |
| **NoPAC** | CVE-2021-42278 / CVE-2021-42287 riski |
| **MSSQL Enumeration** | SPN tabanlı MSSQL sunucu ve servis hesabı keşfi |
| **SCCM/MECM** | System Management container + NAA hesap enumerasyonu |
| **LAPS Passwords** | Okunabilir LAPS şifrelerini LDAP üzerinden çekme |
| **Forest Analysis** | Trust SID filtering, selective auth, FSP, TGT delegation analizi |
| **ADCS ESC9-13** | ESC9 (No Security Extension), ESC10 (Weak Mapping), ESC13 (OID Group Link) |
| **DNSAdmins Chain** | DNSAdmins grubu üyesi → DC'de SYSTEM yetkisi zinciri |
| **CVSS 3.1 Scoring** | Her saldırı zinciri için otomatik CVSS vektörü ve skoru |

#### 🩸 BloodHound Entegrasyonu
- BloodHound CE/Enterprise uyumlu JSON export (`--bh-export`)
- Kullanıcı, grup, bilgisayar, session, local admin, ACL edge'leri
- BloodHound'a doğrudan import edilebilir format

#### 🛠️ Remediation (Düzeltme) Önerileri
Her bulgu için otomatik remediation snippet'leri:
- **MITRE ATT&CK** ID eşlemesi (T1558, T1098, T1484, T1078, T1003, T1557, T1207...)
- Risk seviyesi bazlı önceliklendirme
- Uygulanabilir düzeltme adımları

#### 📊 HTML Rapor
- Etkileşimli dashboard
- Grafik görselleştirme (D3.js tabanlı saldırı grafiği)
- Attack chain detayları
- Filtrelenebilir bulgu tablosu
- JSON ham veri export

### Kurulum

```bash
# Gereksinimler
pip install -r requirements.txt

# requirements.txt içeriği:
# ldap3>=2.9.1
# impacket>=0.11.0
```

### Kullanım

```bash
# Temel kullanım
python3 -m bloodyomain -H <DC_IP> -d <DOMAIN> -u <USERNAME>
# veya modül olarak:
python3 -m bloodyomain -H <DC_IP> -d <DOMAIN> -u <USERNAME>

# Anonim / Null session (kimlik bilgisi gerekmez)
python3 -m bloodyomain -H 192.168.1.10 --anonymous
python3 -m bloodyomain -H 192.168.1.10 --anonymous -o null_session_report.html

# Domain'i otomatik tespit et (anonymous modda)
python3 -m bloodyomain -H 192.168.1.10 --anonymous   # domain RootDSE'den okunur

# Parola spreyi ile
python3 -m bloodyomain -H 192.168.1.10 -d corp.local -u admin --spray --spray-pass "Summer2024!"

# BloodHound export ile
python3 -m bloodyomain -H 192.168.1.10 -d corp.local -u admin --bh-export bh_corp

# JSON + HTML rapor
python3 -m bloodyomain -H 192.168.1.10 -d corp.local -u admin -o report.html -j raw_data.json

# Sadece LDAP (SMB yok)
python3 -m bloodyomain -H 192.168.1.10 -d corp.local -u admin --no-smb

# LDAPS (port 636)
python3 -m bloodyomain -H 192.168.1.10 -d corp.local -u admin --ssl

# Hızlı tarama (gelişmiş kontroller olmadan)
python3 -m bloodyomain -H 192.168.1.10 -d corp.local -u admin --no-advanced

# Çoklu thread
python3 -m bloodyomain -H 192.168.1.10 -d corp.local -u admin --threads 20

# Kerberos auth (KRB5CCNAME ile)
KRB5CCNAME=/tmp/krb5cc_0 python3 -m bloodyomain -H dc01.corp.local -d corp.local -u admin -k

# NetExec hedef listesi + Impacket komut şablonu + Sliver C2 hedefleri
python3 -m bloodyomain -H 192.168.1.10 -d corp.local -u admin \
    --export-netexec netexec_targets.txt \
    --export-impacket impacket_cmds.sh \
    --export-sliver sliver_targets.txt
```

### Parametreler

| Parametre | Açıklama |
|-----------|----------|
| `-H, --host` | LDAP sunucu IP/hostname (**zorunlu**) |
| `-d, --domain` | Domain adı (örn: corp.local) (**zorunlu**) |
| `-u, --user` | Kimlik doğrulama kullanıcı adı (**zorunlu**) |
| `-p, --password` | Parola (belirtilmezse prompt ile sorulur) |
| #### 🔒 Kimlik Doğrulama Seçenekleri

| Mod | Açıklama |
|-----|----------|
| **NTLM (varsayılan)** | Domain kullanıcı adı ve parolası ile tam yetkili bağlantı |
| **Anonymous / Null Session** | Kimlik bilgisi olmadan anonim LDAP bind + SMB null session |
| **LDAPS** | SSL/TLS üzerinden şifreli LDAP (port 636) |
| **Kerberos** | Ticket cache ile Kerberos bağlantısı (`-k`) |

> ⚠️ **Null Session:** Eski/yanlış yapılandırılmış domain controller'larda anonim bağlantı ile kullanıcı, grup, bilgisayar ve paylaşım bilgileri okunabilir. 
> Modern Windows Server'larda (2016+) varsayılan olarak kapalıdır, ancak birçok kurumsal ortamda geriye dönük uyumluluk için hâlâ açıktır.
| `--no-smb` | SMB taramasını atla |
| `--no-advanced` | Gelişmiş kontrolleri atla |
| `--threads N` | Thread sayısı (varsayılan: 10) |
| `--spray` | Parola spreyi yap |
| `--spray-pass` | Spreylenecek parola |
| `--bh-export PREFIX` | BloodHound JSON export prefix |
| `-o, --output` | HTML rapor dosyası (varsayılan: `bloodyomain_report.html`) |
| `-j, --json-out` | Ham JSON verisi kaydet |
| `--no-browser` | Tarayıcıda raporu açma |
| `-k, --kerberos` | Kerberos ticket cache ile bağlan (KRB5CCNAME) |
| `--export-netexec FILE` | NetExec hedef listesi export |
| `--export-impacket FILE` | Impacket komut şablonu export |
| `--export-sliver FILE` | Sliver C2 implant hedef listesi export |

### Gereksinimler

- **Python** 3.8+
- **ldap3** >= 2.9.1 (LDAP bağlantısı ve aramaları)
- **impacket** >= 0.11.0 (SMB/RPC işlemleri — opsiyonel ama şiddetle önerilir)
- Hedef domain controller'a ağ erişimi (LDAP 389/636, SMB 445)
- Geçerli bir domain kullanıcı hesabı (düşük ayrıcalıklı bir hesap dahi pek çok veriyi okuyabilir)

### Tipik İş Akışı

```
1. Domain bilgisi topla        →  LDAP bağlantısı, functional level, DC listesi
2. Kullanıcı/Grup/Bilgisayar   →  Tam enumerasyon, SPN, ASREP, delegation
3. OU/GPO/Trust                →  Organizasyon yapısı ve güven ilişkileri
4. SMB taraması                →  Session, LoggedOn, LocalAdmin, RDP, Shares
5. DACL analizi                →  Kritik objelerde izin analizi
6. ADCS/ADFS/LAPS              →  Sertifika servisi, federation, LAPS
7. Gelişmiş kontroller         →  FGPP, Shadow Crefs, DCSync, AdminSDHolder, GPO
8. Saldırı zinciri analizi     →  36+ otomatik zincir, CRITICAL→LOW
9. Grafik oluşturma            →  D3.js görselleştirme için node/edge verisi
10. Raporlama                  →  HTML interaktif rapor + JSON export
```

### Örnek Çıktı

```
███████╗ ██╗      ██████╗   ██████╗  ██████╗  ██╗   ██╗
██╔══██╗ ██║     ██╔═══██╗ ██╔═══██╗ ██╔══██╗ ╚██╗ ██╔╝
██████╔╝ ██║     ██║   ██║ ██║   ██║ ██║  ██║  ╚████╔╝
██╔══██╗ ██║     ██║   ██║ ██║   ██║ ██║  ██║   ╚██╔╝
██████╔╝ ███████╗╚██████╔╝ ╚██████╔╝ ██████╔╝    ██║
╚═════╝  ╚══════╝ ╚═════╝   ╚═════╝  ╚═════╝     ╚═╝
      ██████╗ ███╗   ███╗  █████╗  ██╗ ███╗   ██╗
      ██╔══██╗████╗ ████║ ██╔══██╗ ██║ ████╗  ██║
      ██║  ██║██╔████╔██║ ███████║ ██║ ██╔██╗ ██║
      ██████╔╝██║╚██╔╝██║ ██╔══██║ ██║ ██║╚██╗██║
      ╚═════╝ ╚═╝     ╚═╝ ╚═╝  ╚═╝ ╚═╝ ╚═╝  ╚═══╝

  [*] LDAP connected: DC01.corp.local
  [+] Users: 1,247 | Groups: 89 | Computers: 342 | OUs: 45
  [+] SPNs: 23 | ASREP: 5 | Tombstoned: 12
  [+] DCSync rights: 3 accounts
  [+] Shadow Credentials: 1 account
  [+] FGPP: 2 policies found
  [+] GPO Write permissions: 4 accounts
  [+] AdminSDHolder ACL: 7 entries
  [+] Description passwords found: 5 (2 high-confidence)
  [+] GPO credentials: 3 (1 cpassword decrypted)
  [+] Validated credentials: 2 valid / 50 tested
  [+] NTLM Relay risk: 2 DC(s) with SMB signing off
  [+] LAPS passwords read: 12 computers
  [!] Attack chains: 34 CRITICAL:8 HIGH:12
  [+] Remediation snippets: 15 (MITRE ATT&CK mapped)
  [+] Viewer data -> viewer/public/data.json
```

### Güvenlik & Etik

Bu araç **yalnızca yetkili** güvenlik testleri için kullanılmalıdır:

- ✅ Yetkili penetrasyon testleri
- ✅ Red team operasyonları
- ✅ Kurum içi Active Directory güvenlik denetimleri
- ✅ CTF ve eğitim amaçlı laboratuvar ortamları
- ❌ İzinsiz sistemlere erişim veya test yapılması yasa dışıdır

### Mimari

```
bloodyomain/                  # Modüler paket (~4,400 satır)
├── __init__.py               # Public API re-export
├── core.py                   # ANSI, log, helpers, sabitler, CVSS, GPP decrypt
├── connector.py              # ADConnector (LDAP) + SMBEngine (SMB/RPC)
├── exporter.py               # BloodHoundExporter — JSON/NetExec/Impacket/Sliver
├── attack_chain.py           # AttackChainEngine — 36+ saldırı zinciri
├── dacl.py                   # DACLAnalyzer — security descriptor parser
├── enumerator.py             # ADEnumerator — ana orkestratör (40+ metod)
└── cli.py                    # argparse + main()
```

### Gelişmiş CLI Parametreleri

```bash
-k, --kerberos              # Kerberos auth via KRB5CCNAME ticket cache
--anonymous                 # Anonim / null session baglantisi
--export-netexec FILE        # NetExec hedef listesi (DC, SignOff, WinRM, RDP)
--export-impacket FILE       # Impacket komut sablonlari (kerberoast, DCSync, RDP)
--export-sliver FILE         # Sliver C2 implant hedef listesi
--threads N                  # Thread sayisi (varsayilan: 10)
```

### Katkı

Katkılar memnuniyetle karşılanır! Lütfen PR göndermeden önce mevcut kod stilini ve yapısını inceleyin.

### Lisans

MIT License — detaylar için [LICENSE](LICENSE) dosyasına bakın.

---

## 🇬🇧 English

### Overview

**Bloodyomain** is a comprehensive Active Directory security audit tool with attack path visualization. It performs deep LDAP and SMB enumeration, automatically analyzes 25+ attack chains, and produces an interactive HTML report.

Designed for penetration testers, red team operators, and AD security auditors.

### Features

#### 🔍 Discovery & Enumeration
| Category | Details |
|----------|---------|
| **Domain Info** | Functional level, machine account quota, domain SID, DC list |
| **Users** | Full attributes, adminCount, SPN, ASREP, enabled/disabled status |
| **Groups** | Nested group resolution, adminCount, Protected Users |
| **Computers** | OS version, DC status, delegation types, LAPS, RDP state |
| **OU & GPO** | Organizational Unit tree, GPO links |
| **Trusts** | Cross-forest trust relationships and direction |
| **Tombstoned** | Deleted objects still within tombstone lifetime |
| **SPN / ASREP** | Kerberoastable and ASREPRoastable accounts |
| **ADCS** | Certificate authorities, templates, ESC1-ESC8 classification |
| **ADFS** | Federation service configuration |
| **LAPS** | LAPS reader groups and authorized accounts |
| **Schema / Enterprise Admins** | High-privilege group memberships |
| **Service Accounts** | SPN-based service account mapping |

<details>
<summary><b>📋 Full Enumeration List (click to expand)</b></summary>

| # | Method | Description |
|---|--------|-------------|
| 1 | `_enum_domain` | Domain functional level, machine quota, DC list |
| 2 | `_enum_users` | User attributes: UAC, lastLogon, pwdLastSet, memberOf, adminCount |
| 3 | `_enum_tombstoned` | Deleted objects (tombstone) |
| 4 | `_enum_groups` | Group memberships and adminCount |
| 5 | `_enum_protected_users` | Protected Users group members |
| 6 | `_resolve_nested_groups` | Nested group resolution |
| 7 | `_check_ldap_security` | LDAP signing and channel binding status |
| 8 | `_enum_computers` | Computers: OS, SP, delegation, LAPS, RDP |
| 9 | `_enum_ous_gpos` | OU tree and GPO links |
| 10 | `_enum_admins` | Domain/Enterprise Admins + Administrators members |
| 11 | `_report_spns` | Kerberoastable accounts |
| 12 | `_report_asrep` | ASREPRoastable accounts |
| 13 | `_check_nopac` | NoPAC (CVE-2021-42278/42287) risk assessment |
| 14 | `_enum_trusts` | Cross-forest trusts |
| 15 | `_enum_dacls` | DACL analysis on critical objects |
| 16 | `_enum_adcs` | ADCS ESC1-ESC8 detection |
| 17 | `_enum_adfs` | ADFS server and configuration |
| 18 | `_enum_laps_readers` | LAPS reader permissions |
| 19 | `_enum_schema_enterprise_admins` | Schema/Enterprise Admin memberships |
| 20 | `_map_service_accounts` | Service account → SPN mapping |
| 21 | `_check_coercion_targets` | PrinterBug / PetitPotam coercion targets |
| 22 | `_check_ntlm_relay_risk` | SMB signing off on DCs → NTLM Relay risk |
| 23 | `_build_delegation_matrix` | Delegation matrix |
| 24 | `_enum_shadow_creds` | msDS-KeyCredentialLink (Shadow Credentials) |
| 25 | `_enum_dcsync_rights` | DCSync rights (Replicating Changes) |
| 26 | `_enum_fgpp` | Fine-Grained Password Policy |
| 27 | `_enum_gpo_write_perms` | GPO write permissions |
| 28 | `_enum_adminsdholder` | AdminSDHolder ACL analysis |
| 29 | `_enum_sensitive_files` | SYSVOL sensitive file scan |
| 30 | `_vuln_scan` | Vulnerability scan |
| 31 | `_enum_exchange_perms` | Exchange Windows Permissions → DCSync |
| 32 | `_password_spray` | Password spray |
| 33 | `_build_remediation` | MITRE ATT&CK-mapped remediation snippets |
| 34 | `_scan_description_passwords` | Description field credential scanner |
| 35 | `_enum_gpo_contents` | SYSVOL GPO crawler — cpassword decrypt + script cred hunt |
| 36 | `_validate_credentials` | Test all discovered credentials via LDAP/SMB/WinRM |
| 37 | `_enum_ou_dacls` | OU container ACL analysis |
| 38 | `_enum_mssql` | MSSQL server + service account discovery (SPN-based) |
| 39 | `_enum_sccm` | SCCM/MECM site server + NAA account enumeration |
| 40 | `_read_laps_passwords` | LAPS password reading via LDAP |

</details>

#### 🔗 SMB Scanning
| Feature | Description |
|----------|-------------|
| **Session Enumeration** | Active SMB sessions across all hosts |
| **LoggedOn Users** | Currently logged-on users per host |
| **Local Admin** | Local administrator group members per host |
| **Share Enumeration** | Shared folders and permissions |
| **RDP Scanning** | RDP (3389) open hosts and Remote Desktop Users |
| **SMB Signing** | SMB signing status (relay attack surface) |
| **Spooler** | Print Spooler service status |
| **ZeroLogon** | ZeroLogon (CVE-2020-1472) vulnerability check |
| **WinRM** | WinRM (5985) reachability |

#### ⛓️ Attack Chain Analysis (36+ Chains)

Bloodyomain analyzes collected data and automatically builds these attack chains, classified as `CRITICAL` / `HIGH` / `MEDIUM` / `LOW`:

| # | Attack Chain | Description |
|---|--------------|-------------|
| 1 | **Privileged Session** | Hosts with active DA sessions |
| 2 | **Local Admin → DA** | Hosts where you're local admin and DA has a session |
| 3 | **RDP → DA Session** | RDP-accessible hosts with DA sessions |
| 4 | **Kerberoast** | High-privilege accounts with SPNs |
| 5 | **ASREP Roast** | Accounts without Kerberos pre-authentication |
| 6 | **Unconstrained Delegation** | Unconstrained delegation risks |
| 7 | **Constrained Delegation** | Constrained delegation risks |
| 8 | **RBCD** | Resource-Based Constrained Delegation |
| 9 | **ACL Chains** | Critical ACL relationships (GenericAll, WriteOwner, WriteDacl) |
| 10 | **Password Policy** | Weak password policy risks |
| 11 | **Stale Accounts** | Old/untouched accounts |
| 12 | **Nested Group** | Excessively deep nested group risks |
| 13 | **Machine Quota** | Default machine account quota risk |
| 14 | **ADCS (ESC1-8)** | Certificate service attack paths |
| 15 | **Password Not Req** | Password-not-required accounts |
| 16 | **AdminCount** | Critical adminCount=1 accounts |
| 17 | **Pwd Never Expires** | Non-expiring password accounts |
| 18 | **Shadow Credentials** | msDS-KeyCredentialLink risks |
| 19 | **GPO Write** | Accounts with GPO write access |
| 20 | **AdminSDHolder** | AdminSDHolder ACL abuse |
| 21 | **Silver Ticket** | Silver ticket preconditions |
| 22 | **S4U** | S4U2Self/S4U2Proxy abuse |
| 23 | **KRBRelay** | KRBRelay-suitable servers |
| 24 | **PrintNightmare** | Print Spooler + write permissions |
| 25 | **ZeroLogon → DCSync** | Domain admin via ZeroLogon |
| 26 | **Exchange → DCSync** | DCSync via Exchange Windows Permissions |
| 27 | **Delegation-Aware** | Delegation-based composite chains |
| 28 | **Description Credential** | Passwords found in user descriptions |
| 29 | **GPO Credential** | Credentials found in GPO/SYSVOL files |
| 30 | **Validated Credential** | Tested & confirmed valid credentials |
| 31 | **OU ACL Abuse** | OU-level GenericAll/WriteOwner detection |
| 32 | **DNSAdmins Abuse** | DNSAdmins → DC SYSTEM via DLL injection |
| 33 | **Cross-Forest SID Abuse** | SID filtering OFF on trust → cross-forest admin |
| 34 | **MSSQL Chain** | MSSQL service account → Kerberoast → DA |
| 35 | **SCCM Chain** | SCCM NAA account → local admin on all clients |
| 36 | **LAPS Chain** | LAPS readable computers + DA session = CRITICAL |

#### 🛡️ DACL Analyzer
- Custom DACL/ACE parser (security descriptor control)
- Critical right detection: `GenericAll`, `WriteOwner`, `WriteDacl`, `WriteProperty`, `ExtendedRight`, `AddMember`, `ForceChangePassword`
- Focus on high-value targets: Domain Admins, Enterprise Admins, AdminSDHolder

#### 🕵️ Credential Hunting
| Feature | Description |
|----------|-------------|
| **Description Scanner** | 12+ regex patterns for passwords in user description fields (Turkish + English) |
| **GPO/SYSVOL Crawler** | cpassword AES decrypt from Groups.xml/Services.xml + .bat/.ps1/.vbs hardcoded credentials |
| **Credential Validator** | Test discovered credentials via LDAP bind + WinRM/SMB verification |

#### 🔬 Advanced Auditing
| Feature | Description |
|----------|-------------|
| **DCSync Rights** | Replicating Changes rights on domain controllers |
| **FGPP** | Fine-Grained Password Policy analysis |
| **Shadow Credentials** | msDS-KeyCredentialLink attribute scanning |
| **AdminSDHolder** | ACL entries on AdminSDHolder object |
| **GPO Write Perms** | Write permissions on GPOs |
| **OU Container ACLs** | GenericAll/WriteOwner/WriteDACL analysis on OUs |
| **Sensitive Files** | Password/secret-containing files on SYSVOL |
| **Coercion Targets** | PrinterBug / PetitPotam suitable hosts |
| **PrinterNightmare Deep** | Spooler + PointAndPrint + RpcAuthnLevel details |
| **NTLM Relay** | SMB signing off on DCs → NTLM Relay risk |
| **NoPAC** | CVE-2021-42278 / CVE-2021-42287 risk |
| **MSSQL Enumeration** | SPN-based MSSQL server + service account discovery |
| **SCCM/MECM** | System Management container + NAA account enumeration |
| **LAPS Passwords** | Read LAPS passwords via LDAP (if authorized) |
| **Forest Analysis** | Trust SID filtering, selective auth, FSP, TGT delegation |
| **ADCS ESC9-13** | ESC9 (No Security Extension), ESC10 (Weak Mapping), ESC13 (OID Group Link) |
| **DNSAdmins Chain** | DNSAdmins member → DC SYSTEM (dns.exe DLL injection) |
| **CVSS 3.1 Scoring** | Automatic CVSS vector + score for every attack chain |

#### 🩸 BloodHound Integration
- BloodHound CE/Enterprise compatible JSON export (`--bh-export`)
- Users, groups, computers, sessions, local admins, ACL edges
- Directly importable into BloodHound

#### 🛠️ Remediation Snippets
Automatic remediation suggestions for each finding:
- **MITRE ATT&CK** ID mapping (T1558, T1098, T1484, T1078, T1003, T1557, T1207...)
- Risk-level based prioritization
- Actionable fix steps

#### 📊 HTML Report
- Interactive dashboard
- Graph visualization (D3.js-based attack graph)
- Attack chain details
- Filterable findings table
- Raw JSON export

### Installation

```bash
# Requirements
pip install -r requirements.txt

# requirements.txt contents:
# ldap3>=2.9.1
# impacket>=0.11.0
```

### Usage

```bash
# Basic usage
python3 -m bloodyomain -H <DC_IP> -d <DOMAIN> -u <USERNAME>
# Or as a module:
python3 -m bloodyomain -H <DC_IP> -d <DOMAIN> -u <USERNAME>

# With password spray
python3 -m bloodyomain -H 192.168.1.10 -d corp.local -u admin --spray --spray-pass "Summer2024!"

# With BloodHound export
python3 -m bloodyomain -H 192.168.1.10 -d corp.local -u admin --bh-export bh_corp

# JSON + HTML report
python3 -m bloodyomain -H 192.168.1.10 -d corp.local -u admin -o report.html -j raw_data.json

# LDAP only (no SMB)
python3 -m bloodyomain -H 192.168.1.10 -d corp.local -u admin --no-smb

# LDAPS (port 636)
python3 -m bloodyomain -H 192.168.1.10 -d corp.local -u admin --ssl

# Quick scan (skip advanced checks)
python3 -m bloodyomain -H 192.168.1.10 -d corp.local -u admin --no-advanced

# Multi-threaded
python3 -m bloodyomain -H 192.168.1.10 -d corp.local -u admin --threads 20

# Kerberos auth via ticket cache
KRB5CCNAME=/tmp/krb5cc_0 python3 -m bloodyomain -H dc01.corp.local -d corp.local -u admin -k

# Export NetExec targets, Impacket commands, Sliver C2 targets
python3 -m bloodyomain -H 192.168.1.10 -d corp.local -u admin \
    --export-netexec netexec_targets.txt \
    --export-impacket impacket_cmds.sh \
    --export-sliver sliver_targets.txt
```

### Parameters

| Parameter | Description |
|-----------|-------------|
| `-H, --host` | LDAP server IP/hostname (**required**) |
| `-d, --domain` | Domain name (e.g. corp.local) (**required**) |
| `-u, --user` | Authentication username (**required**) |
| `-p, --password` | Password (prompt if omitted) |
| `--ssl` | Use LDAPS (port 636) |
| `--no-smb` | Skip all SMB enumeration |
| `--no-advanced` | Skip advanced checks (FGPP, Shadow Creds, DCSync, etc.) |
| `--threads N` | Thread count (default: 10) |
| `--spray` | Perform password spray |
| `--spray-pass` | Password to spray |
| `--bh-export PREFIX` | BloodHound JSON export prefix |
| `-o, --output` | HTML report file (default: `bloodyomain_report.html`) |
| `-j, --json-out` | Save raw JSON data |
| `--no-browser` | Do not open report in browser |
| `-k, --kerberos` | Use Kerberos ticket cache (KRB5CCNAME) |
| `--export-netexec FILE` | Export NetExec target list |
| `--export-impacket FILE` | Export Impacket command templates |
| `--export-sliver FILE` | Export Sliver C2 implant target list |

### Requirements

- **Python** 3.8+
- **ldap3** >= 2.9.1 (LDAP connectivity and queries)
- **impacket** >= 0.11.0 (SMB/RPC operations — optional but strongly recommended)
- Network access to target domain controller (LDAP 389/636, SMB 445)
- A valid domain user account (even a low-privileged account can read most data)

### Typical Workflow

```
1. Domain info gathering       →  LDAP connection, functional level, DC list
2. Users/Groups/Computers      →  Full enumeration, SPN, ASREP, delegation
3. OU/GPO/Trust                →  Organizational structure and trust relationships
4. SMB scanning                →  Sessions, LoggedOn, LocalAdmin, RDP, Shares
5. DACL analysis               →  Permission analysis on critical objects
6. ADCS/ADFS/LAPS              →  Certificate services, federation, LAPS
7. Advanced checks             →  FGPP, Shadow Creds, DCSync, AdminSDHolder, GPO
8. Attack chain analysis       →  36+ automatic chains, CRITICAL→LOW
9. Graph construction          →  Node/edge data for D3.js visualization
10. Reporting                  →  HTML interactive report + JSON export
```

### Sample Output

```
  [*] LDAP connected: DC01.corp.local
  [+] Users: 1,247 | Groups: 89 | Computers: 342 | OUs: 45
  [+] SPNs: 23 | ASREP: 5 | Tombstoned: 12
  [+] DCSync rights: 3 accounts
  [+] Shadow Credentials: 1 account
  [+] FGPP: 2 policies found
  [+] GPO Write permissions: 4 accounts
  [+] AdminSDHolder ACL: 7 entries
  [+] Description passwords found: 5 (2 high-confidence)
  [+] GPO credentials: 3 (1 cpassword decrypted)
  [+] Validated credentials: 2 valid / 50 tested
  [+] NTLM Relay risk: 2 DC(s) with SMB signing off
  [+] LAPS passwords read: 12 computers
  [!] Attack chains: 34 CRITICAL:8 HIGH:12
  [+] Remediation snippets: 15 (MITRE ATT&CK mapped)
  [+] Viewer data -> viewer/public/data.json
```

### Security & Ethics

This tool should **only** be used for authorized security testing:

- ✅ Authorized penetration tests
- ✅ Red team operations
- ✅ Internal Active Directory security audits
- ✅ CTF and lab/training environments
- ❌ Unauthorized access to or testing of systems is illegal

### Architecture

```
bloodyomain/                  # Modular package (~4,400 lines)
├── __init__.py               # Public API re-exports
├── core.py                   # ANSI, log, helpers, constants, CVSS, GPP decrypt
├── connector.py              # ADConnector (LDAP) + SMBEngine (SMB/RPC)
├── exporter.py               # BloodHoundExporter — JSON/NetExec/Impacket/Sliver
├── attack_chain.py           # AttackChainEngine — 36+ attack chains
├── dacl.py                   # DACLAnalyzer — security descriptor parser
├── enumerator.py             # ADEnumerator — main orchestrator (40+ methods)
└── cli.py                    # argparse + main()
```

### Contributing

Contributions welcome! Please review existing code style and structure before submitting PRs.

### License

MIT License — see [LICENSE](LICENSE) file for details.
