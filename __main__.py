# operation_data_shield.py
import re
import base64
import codecs


# =========== Role 1: 🕵 Financial Detective ==========

def luhn_check(card_number: str) -> bool:
    """
     Checking the card number using the Luna algorithm.
     Algorithm:
     1. Go from right to left
     2. Double every second digit
     3. If the result is > 9, subtract 9
     4. The sum of all digits must be divisible by 10
     """
    try:
        digits = [int(d) for d in card_number]

        # We start from the end and double every second digit
        for i in range(len(digits) - 2, -1, -2):
            digits[i] *= 2
            if digits[i] > 9:
                digits[i] -= 9

        return sum(digits) % 10 == 0
    except (ValueError, IndexError):
        return False

def find_and_validate_credit_cards(text):
    """
    finds card numbers in the text and checks them using the Luna algorithm.
    text: Text to search for card numbers
    returns:Dictionary with valid and invalid cards
    """
    valid_cards = []
    invalid_cards = []
    pattern = r"(?:\d[ -]?){16}" #the general pattern of the cards
    raw_cards = re.findall(pattern, text)
    for card in raw_cards:
        clean = re.sub(r"[ -]", "", card) #It changes cons and spaces to nothing
        if len(clean) != 16 or not clean.isdigit():
            invalid_cards.append(clean)
            continue
        if luhn_check(clean):
            valid_cards.append(clean)
        else:
            invalid_cards.append(clean)
    return {"valid": valid_cards, "invalid": invalid_cards}

with open('data_leak_sample.txt', 'r', encoding='utf-8') as f:
    text = f.read()
    print('НОМЕРА БАНКОВСКИХ КАРТ: ', find_and_validate_credit_cards(text))


# ========== Role 2: 🔐 Key Hunter ==========
def find_secrets(text):
    secrets = []
    result = []
    api_patterns = [
        # Stripe
        r'sk_live_[a-zA-Z0-9]{24,}',
        r'sk_test_[a-zA-Z0-9]{24,}',
        r'pk_live_[a-zA-Z0-9]{24,}',
        r'pk_test_[a-zA-Z0-9]{24,}',
        r'rk_live_[a-zA-Z0-9]{24,}'
    ]

    for pattern in api_patterns:
        secrets.extend(re.findall(pattern, text))

    for secret in secrets:
        if secret not in result:
            result.append(secret)

    for word in text.split():
        if (not re.fullmatch(r'\d+', word)
            and not re.fullmatch(r'[A-Za-z]+', word)
            and not re.fullmatch(r'[!@#$%^&*]', word)
            and re.fullmatch(r'[A-Za-z0-9!@#$%^&*]+', word)):
            result.append(word)
    return list(set(result))

with open('data_leak_sample.txt', 'r', encoding='utf-8') as f:
    main_text = f.read()
    print('СЕКРЕТЫ: ',find_secrets(main_text))


# ========== Role 3: 💻 System Information Tracker ==========

def find_system_info(text):
    results = {
        'ips': [],
        'files': [],
        'emails': []
    }

    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    results['ips'] = list(set(re.findall(ip_pattern, text)))
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    results['emails'] = list(set(re.findall(email_pattern, text)))
    file_pattern = r'(?:[a-zA-Z]:\\|/)(?:[\w\s\d.-_]+\\)*[\w\s\d.-_]+\.[a-zA-Z0-9]+'
    results['files'] = list(set(re.findall(file_pattern, text)))

    return results

with open('data_leak_sample.txt', 'r', encoding='utf-8') as f:
    main_text = f.read()
    print('СИСТЕМНАЯ ИНФОРМАЦИЯ: ',find_system_info(main_text))

'''
def generate_comprehensive_report(main_text, log_text, messy_data):
    """ Генерирует полный отчет о расследовании """
    report = { 'financial_data': find_and_validate_credit_cards(main_text),
               'secrets': find_secrets(main_text),
               'system_info': find_system_info(main_text),
               'encoded_messages': decode_messages(main_text),
               'security_threats': analyze_logs(log_text),
               'normalized_data': normalize_and_validate(messy_data)
               }
    return report


def print_report(report):
    """Красиво выводит отчет"""
    print("=" * 50)
    print("ОТЧЕТ ОПЕРАЦИИ 'DATA SHIELD'")
    print("=" * 50)
    # Вывод результатов каждой роли
    sections = [ ("ФИНАНСОВЫЕ ДАННЫЕ", report['financial_data']),
                 ("СЕКРЕТНЫЕ КЛЮЧИ", report['secrets']),
                 ("СИСТЕМНАЯ ИНФОРМАЦИЯ", report['system_info']),
                 ("РАСШИФРОВАННЫЕ СООБЩЕНИЯ", report['encoded_messages']),
                 ("УГРОЗЫ БЕЗОПАСНОСТИ", report['security_threats']),
                 ("НОРМАЛИЗОВАННЫЕ ДАННЫЕ", report['normalized_data']) ]
    for title, data in sections:
        print(f"\n{title}:")
        print("-" * 30)
        # Детальный вывод данных...

if __name__ == "__main__":
    # Чтение файлов с данными
    with open('data_leak_sample.txt', 'r', encoding='utf-8') as f:
        main_text = f.read()
    with open('web_server_logs.txt', 'r', encoding='utf-8') as f:
        log_text = f.read()
    with open('messy_data.txt', 'r', encoding='utf-8') as f:
        messy_data = f.read()
        # Запуск расследования
        report = generate_comprehensive_report(main_text, log_text, messy_data)
        print_report(report)
'''