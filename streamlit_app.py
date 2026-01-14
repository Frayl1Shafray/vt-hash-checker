import streamlit as st
import re
import requests
import time
import pandas as pd

# --- Налаштування інтерфейсу ---
st.set_page_config(page_title="VT Hash Converter", page_icon="🛡️")
st.title("Екстрактор хешів та VT Checker")

# Отримання API ключа з налаштувань Streamlit Cloud
VT_API_KEY = st.secrets.get("VT_API_KEY", "")
def extract_hashes(text):
    """Знаходить унікальні MD5 та SHA256 у тексті."""
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    
    # Використовуємо set для унікальності, потім перетворюємо в list
    md5_list = list(dict.fromkeys(re.findall(md5_pattern, text)))
    sha256_list = list(dict.fromkeys(re.findall(sha256_pattern, text)))
    
    return md5_list, sha256_list

def get_sha1_from_vt(md5_hash):
    """Один запит до VirusTotal API."""
    url = f'https://www.virustotal.com/api/v3/files/{md5_hash}'
    headers = {'x-apikey': VT_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()['data']['attributes'].get('sha1', '')
        return ''
    except Exception:
        return ''

# --- Блок введення даних ---
description_obj = st.text_input("Опис (Description):", "Аналіз шкідливого ПЗ")
input_text = st.text_area("Вставте текст із хешами тут:", height=300)

if st.button("Обробити дані", type="primary"):
    if not input_text.strip():
        st.error("Будь ласка, вставте текст.")
    elif not VT_API_KEY:
        st.error("API ключ не налаштовано в Secrets!")
    else:
        # 1. Знаходимо всі хеші
        md5_hashes, sha256_hashes = extract_hashes(input_text)
        
        if not md5_hashes and not sha256_hashes:
            st.warning("У тексті не знайдено жодного MD5 або SHA256.")
        else:
            st.info(f"Знайдено MD5: {len(md5_hashes)} | SHA256: {len(sha256_hashes)}")
            
            final_data = []
            progress_bar = st.progress(0)
            status_text = st.empty()

            # 2. Цикл обробки MD5 через VirusTotal
            for i, md5 in enumerate(md5_hashes):
                # Оновлення прогресу
                progress_val = (i + 1) / len(md5_hashes)
                progress_bar.progress(progress_val)
                status_text.text(f"Запит до VT для: {md5} ({i+1}/{len(md5_hashes)})")
                
                sha1 = get_sha1_from_vt(md5)
                
                if sha1:
                    final_data.append({'Type': 'sha1', 'Object': sha1, 'Description': description_obj})
                else:
                    # Якщо SHA1 не знайдено, спробуємо взяти SHA256 (якщо є в списку за тим же індексом)
                    fallback = sha256_hashes[i] if i < len(sha256_hashes) else ""
                    if fallback:
                        final_data.append({'Type': 'sha256', 'Object': fallback, 'Description': description_obj})
                
                # Затримка 15 сек для безкоштовного API (4 запити/хв)
                if i < len(md5_hashes) - 1:
                    time.sleep(15)

            status_text.success("Обробка завершена!")

            # 3. Відображення результатів та завантаження
            if final_data:
                df = pd.DataFrame(final_data)
                st.subheader("Результати:")
                st.dataframe(df, use_container_width=True)

                csv = df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="Завантажити CSV результати",
                    data=csv,
                    file_name="vt_results.csv",
                    mime="text/csv"
                )
            else:
                st.warning("Не вдалося отримати додаткові дані для знайдених хешів.")