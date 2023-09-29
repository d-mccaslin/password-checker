# Password Checker

import hashlib
import requests


def get_password():
    while True:
        password = input("Enter your password: ")
        if len(password) >= 8:
            return password
        else:
            print("Password is too short. Please try again.")


def hash_password(message):
    hash_result = hashlib.sha1()
    hash_result.update(message.encode("utf-8"))
    hashed_password = hash_result.hexdigest()
    print(f'Your hashed password is: {hashed_password}')
    return hashed_password


def check_if_pwned(password_hash, original):
    print("Checking...")
    password_hash_prefix = password_hash[0:5]
    password_hash_suffix = password_hash[5:]

    base_url = 'https://api.pwnedpasswords.com/range/'
    url = base_url + password_hash_prefix
    headers = {
        "Add-Padding": "true"
    }

    response = requests.get(url=url, headers=headers)
    print(f'A request was sent to "{url}" endpoint, awaiting response...')

    if response.status_code == 200:
        response_string = response.text.lower()
        # print(response_string)
        if password_hash_suffix in response_string:
            hashes = response_string.split("\n")
            hashes_stripped = []

            for i in hashes:
                h = i.rstrip()
                hashes_stripped.append(h)
            # print(hashes_stripped)

            for i in hashes_stripped:
                if password_hash_suffix in i:
                    length = len(password_hash_suffix) + 1
                    breach_count = i[length:]
                    print(f'Your password has been pwned! The password "{original}" appears {breach_count} times in data breaches.')
        else:
            print("Good news! Your password hasn't been pwned.")
    else:
        print("Invalid request.")


if __name__ == "__main__":
    password = get_password()
    hashed_password = hash_password(password)
    check_if_pwned(hashed_password, password)
