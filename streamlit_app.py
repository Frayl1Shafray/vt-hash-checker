import streamlit as st
import re
import requests
import time
import pandas as pd

# --- Налаштування інтерфейсу ---
st.set_page_config(page_title="Vision One Security", page_icon="🛡️", layout="wide")

# Отримання API ключі
VT_API_KEY = st.secrets.get("VT_API_KEY", "")
IPQS_KEY = st.secrets.get("IPQS_KEY", "")

def extract_hashes(text):
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    # Використовуємо dict.fromkeys для збереження черговості та унікальності
    md5_list = list(dict.fromkeys(re.findall(md5_pattern, text)))
    sha256_list = list(dict.fromkeys(re.findall(sha256_pattern, text)))
    return md5_list, sha256_list

def check_ip_quality(ip):
    url = f"https://www.ipqualityscore.com/api/json/ip/{IPQS_KEY}/{ip}"
    params = {'strictness': 0, 'allow_public_access_points': 'true'}
    try:
        resp = requests.get(url, params=params, timeout=10)
        return resp.json() if resp.status_code == 200 else None
    except: return None

def get_sha1_from_vt(md5_hash):
    url = f'https://www.virustotal.com/api/v3/files/{md5_hash}'
    headers = {'x-apikey': VT_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()['data']['attributes'].get('sha1', '')
        return ''
    except Exception: return ''

# --- Навігація ---
with st.sidebar:
    st.title("🛡️ SOC tools")
    choice = st.radio("Оберіть інструмент:", ["Hash Analysis", "IP Security Module"])
    st.divider()
    if not VT_API_KEY or not IPQS_KEY:
        st.warning("⚠️ Деякі API ключі відсутні в Secrets!")

# --- Вкладка 1: Хеші ---
if choice == "Hash Analysis":
    st.header("🔎 Hash Analysis Module")
    description_obj = st.text_input("Опис (Description):", "Аналіз шкідливого ПЗ")
    input_text = st.text_area("Вставте текст із хешами тут:", height=300)

    if st.button("Обробити дані", type="primary"):
        if not input_text.strip():
            st.error("Будь ласка, вставте текст.")
        else:
            md5_hashes, sha256_hashes = extract_hashes(input_text)
            
            if not md5_hashes and not sha256_hashes:
                st.warning("Хеші не знайдено.")
            else:
                final_data = []
                
                # Спочатку додаємо всі знайдені SHA256 (вони вже готові)
                for s256 in sha256_hashes:
                    final_data.append({'Type': 'sha256', 'Object': s256, 'Description': description_obj})
                
                # Тепер обробляємо MD5 -> SHA1
                if md5_hashes:
                    if not VT_API_KEY:
                        st.error("Ключ VirusTotal не знайдено. Перетворення MD5 пропущено.")
                    else:
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        for i, md5 in enumerate(md5_hashes):
                            status_text.text(f"Запит до VT для MD5: {md5} ({i+1}/{len(md5_hashes)})")
                            sha1 = get_sha1_from_vt(md5)
                            
                            if sha1:
                                final_data.append({'Type': 'sha1', 'Object': sha1, 'Description': description_obj})
                            
                            progress_bar.progress((i + 1) / len(md5_hashes))
                            # Затримка тільки якщо є наступний хеш
                            if i < len(md5_hashes) - 1:
                                time.sleep(15)
                        status_text.success("Обробка MD5 завершена!")

                if final_data:
                    df = pd.DataFrame(final_data)
                    st.subheader("Результати:")
                    st.dataframe(df, use_container_width=True)
                    st.download_button("Завантажити CSV", df.to_csv(index=False).encode('utf-8'), "vt_results.csv", "text/csv")

# --- Вкладка 2: IP Security Module ---
elif choice == "IP Security Module":
    st.header("IP Security Investigation")
    ip_input = st.text_input("Введіть IP для перевірки:", placeholder="8.8.8.8")

    if st.button("Перевірити репутацію") and ip_input:
        if not IPQS_KEY:
            st.error("Ключ IPQualityScore не налаштовано!")
        else:
            with st.spinner('Запит до IPQualityScore...'):
                data = check_ip_quality(ip_input)
                if data and data.get('success'):
                    score = data.get('fraud_score', 0)
                    m1, m2, m3 = st.columns(3)
                    m1.metric("Fraud Score", f"{score}/100", "High Risk" if score > 75 else "Safe", delta_color="inverse")
                    m2.metric("Bot Status", "🤖 Bot" if data.get('bot_status') else "✅ Clean")
                    m3.metric("Recent Abuse", "🚨 Yes" if data.get('recent_abuse') else "✅ No")

                    st.subheader("Security Verdicts")
                    c1, c2, c3 = st.columns(3)
                    with c1: st.info(f"VPN: {'🔴 Yes' if data.get('vpn') else '🟢 No'}")
                    with c2: st.info(f"Proxy: {'🔴 Yes' if data.get('proxy') else '🟢 No'}")
                    with c3: st.info(f"Tor: {'🔴 Yes' if data.get('tor') else '🟢 No'}")

                    st.subheader("🏢 Infrastructure")
                    st.table({
                        "Параметр": ["ISP", "Organization", "Location", "ASN"],
                        "Значення": [data.get('ISP'), data.get('organization'), f"{data.get('city')}, {data.get('country_code')}", data.get('ASN')]
                    })
                    st.divider()
                    # 3. Генерація шаблону повідомлення
                    st.subheader("Шаблон сповіщення")
                    
                    city = data.get('city', 'Unknown City')
                    country = data.get('country_code', 'Unknown Country')
                    
                    # Формуємо текст з виділеним місцем під сервіс
                    template = (
                        f"Вітаю!\n\n"
                        f"З Вашого облікового запису було здійснено вхід з IP-адреси {ip_input} "
                        f"(Локація: {city}, {country}) до сервісу [ВСТАВТЕ НАЗВУ СЕРВІСУ].\n\n"
                    )
                    
                    # Виводимо в полі для копіювання
                    st.text_area("Скопіюйте та відредагуйте текст:", value=template, height=160)
                    st.caption("Порада: після копіювання замініть текст у квадратних дужках на назву вашого сервісу.")
                else:
                    st.error("Помилка API або невірний IP.")