import re

#REGEX PATTERNS
#Each pattern describes the "shape" of one PII type.
PATTERNS = {
    "email": re.compile(r"[\w.-]+@[\w.-]+\.\w+"),
    "phone_au": re.compile(r"(?:\+61|0)[ .\-]?[2-478](?:[ .\-]?\d){8}"),
    "credit_card": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
}


#LUHN ALGORITHM 
def is_luhn_valid(card_number: str) -> bool:
    digits = [int(d) for d in re.sub(r"[ -]", "", card_number)]
    total = 0
    #reverse so index 0 = rightmost digit
    digits.reverse()

    for i, digit in enumerate(digits):
        if i % 2 == 1:  #every second digit from the right
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit

    return total % 10 == 0


#DETECTION FUNCTIONS 
def find_emails(text: str) -> list:
    return PATTERNS["email"].findall(str(text))


def find_phones(text: str) -> list:
    return PATTERNS["phone_au"].findall(str(text))


def find_credit_cards(text: str) -> list:
    candidates = PATTERNS["credit_card"].findall(str(text))
    valid_cards = [c for c in candidates if is_luhn_valid(c)]
    return valid_cards


#QUICK SELF-TEST
if __name__ == "__main__":
    test_email = "Contact me at john.doe@example.com please"
    test_phone = "Call 0412 345 678 today"
    test_card = "Card: 4539 1488 0343 6467"

    print("Emails found:", find_emails(test_email))
    print("Phones found:", find_phones(test_phone))
    print("Cards found:", find_credit_cards(test_card))
