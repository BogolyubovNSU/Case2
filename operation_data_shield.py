import re
import base64
import codecs


def luhn_check(card_number: str) -> bool:
    """
    Function. Checks the bank card number using the Luhn algorithm.
    :param card_number: the string containing the bank card number

    :return: True or False
    """
    card_number = re.sub(r'\D', '', card_number)
    digits = [int(dgt) for dgt in card_number]

    for index in range(len(digits) - 2, -1, -2):
        digits[index] *= 2
        if digits[index] > 9:
            digits[index] -= 9

    return sum(digits) % 10 == 0


def find_and_validate_credit_cards(text: str) -> set[str]:
    """
    Function. It finds card numbers and checks them using the Luhn algorithm.
    :param text: a string where you can find bank card numbers

    :return: numbers of bank cards that passed and failed the Luhn algorithm
    """
    valid_cards = []
    invalid_cards = []

    for match in re.finditer(r'(\d{4}[ -]?){4}', text):
        card_number = match.group()
        if luhn_check(card_number):
            valid_cards.append(card_number)
        else:
            invalid_cards.append(card_number)

    return {f'valid: {valid_cards}, invalid: {invalid_cards}'}


def find_secrets(text: str) -> set[str]:
    """
    Function. Finds API keys and passwords.
    :param text: a string where you can find API keys and passwords

    :return: API keys and passwords
    """
    result = []

    # API KEY SEARCH
    api_pattern = r'(?:sk|pk|rk)_(?:live|test)_[a-zA-Z0-9]{24,}'
    for match in re.finditer(api_pattern, text):
        result.append(match.group())

    # PASSWORD SEARCH
    for data in text.split('\n'):
        if (not re.fullmatch(r'\d+', data)
            and not re.fullmatch(r'[A-Za-z]+', data)
            and not re.fullmatch(r'[!@#$%^&*]', data)
            and re.fullmatch(r'[A-Za-z0-9!@#$%^&*]+', data)):
            result.append(data)

    return set(result)


def find_system_info(text: str) -> dict[str, set[str]]:
    """
    Function. Finds IPv4, files, and email.
    :param text: a string where you can find IPv4, files, and email

    :return: IPv4, files, and email
    """
    text = text.split('\n')
    results = {
        'IPv4': set(),
        'files': set(),
        'emails': set()
    }

    # IPV4 SEARCH
    acceptable_values_in_ipv4 = r'(?:[1-9]?\d|1\d\d|2[0-4]\d|25[0-5])'
    ip_pattern = ((acceptable_values_in_ipv4 + '.') * 3
                  + acceptable_values_in_ipv4)

    for data in text:
        if re.fullmatch(ip_pattern, data):
            results['IPv4'].add(data)

    # EMAIL SEARCH
    acceptable_part_of_email = r'[^.-_](?:[a-z0-9]|[^.-_][.-_][^.-_])+[^.-_]'
    top_level_domain = r'\.[a-z]{2,}'
    email_pattern = (acceptable_part_of_email + '@'
                     + acceptable_part_of_email + top_level_domain)

    for data in text:
        if re.fullmatch(email_pattern, data):
            results['emails'].add(data)

    # FILE SEARCH
    file_pattern = r'[A-Z]:\\([\w -.]+\\)*[\w -.]+(\.[^\\/:*?<>|]+)+'

    for data in text:
        if re.fullmatch(file_pattern, data):
            results['files'].add(data)

    return results


def decode_messages(text: str) -> dict[str, set[str]]:
    """
    Function. Finds and decodes messages in ROT13, Base64, and Hex encodings.
    :param text: a string in which you need to find and decrypt messages

    :return: encoded and decoded messages
    """
    text = text.split('\n')
    results = {
        'base64': set(),
        'hex': set(),
        'rot13': set()
    }

    for message in text:
        decoding_in_rot13 = []

        # ROT13 DECODING
        for word in message.split():
            if re.fullmatch(r'[A-Za-z]+', word):
                decoding_in_rot13.append(codecs.decode(word, 'rot13'))
            else:
                decoding_in_rot13.append(word)

        if message.split() != decoding_in_rot13:
            results['rot13'].add(
                f'Encoded: {message}; '
                f'Decoded: {" ".join(decoding_in_rot13)}')

        # BASE64 DECODING
        if (len(message)
                and not len(message) % 4
                and re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', message)):
            try:
                decoded = base64.b64decode(message).decode('utf-8')
                results['base64'].add(
                    f'Encoded: {message}; '
                    f'Decoded: {decoded}')
            except UnicodeDecodeError:
                pass

        # HEX DECODING
        if (not len(message) % 2
                and re.fullmatch(r'0x[0-9A-Fa-f]+', message)):
                decoded = codecs.decode(message[2:], 'hex').decode('utf-8')
                results['hex'].add(
                    f'Encoded: {message}; '
                    f'Decoded: {decoded}')

    return results


def generate_comprehensive_report(text: str) -> dict[str, set[str]]:
    """
    Function. Generates a full investigation report.
    :param text: the file to investigate

    :return: investigation report
    """
    return { 'financial_data': find_and_validate_credit_cards(text),
               'secrets': find_secrets(text),
               'system_info': find_system_info(text),
               'encoded_messages': decode_messages(text),
               }


def print_report(dictionary: dict[str, set[str]]) -> None:
    """
    Function. Prints the report.
    :param dictionary: investigation report

    :return: None
    """
    print("=" * 50)
    print("ОТЧЕТ ОПЕРАЦИИ 'DATA SHIELD'")
    print("=" * 50)
    sections = [ ("ФИНАНСОВЫЕ ДАННЫЕ", dictionary['financial_data']),
                 ("СЕКРЕТНЫЕ КЛЮЧИ", dictionary['secrets']),
                 ("СИСТЕМНАЯ ИНФОРМАЦИЯ", dictionary['system_info']),
                 ("РАСШИФРОВАННЫЕ СООБЩЕНИЯ", dictionary['encoded_messages']) ]

    for title, data in sections:
        print(f"\n{title}:\n{data}")
        print("-" * 30)


if __name__ == "__main__":
    with open('data_leak_sample.txt', 'r', encoding='utf-8') as f:
        main_text = f.read()
        report = generate_comprehensive_report(main_text)
        print_report(report)
        with open('result4.txt', 'w', encoding='utf-8') as file:
            for artefact in report['financial_data']:
                file.write(artefact+'\n')

            for artefact in report['secrets']:
                file.write(artefact+'\n')

            for artefact in report['system_info']['IPv4']:
                file.write(artefact+'\n')

            for artefact in report['system_info']['files']:
                file.write(artefact+'\n')

            for artefact in report['system_info']['emails']:
                file.write(artefact+'\n')

            for artefact in report['encoded_messages']['base64']:
                file.write(artefact+'\n')

            for artefact in report['encoded_messages']['hex']:
                file.write(artefact+'\n')

            for artefact in report['encoded_messages']['rot13']:
                file.write(artefact+'\n')