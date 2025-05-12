import hashlib
import itertools
import string
import os

HASH_ALGORITHMS = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha256': hashlib.sha256
}

def dictionary_attack(hash_value, hash_algorithm, dictionary_file):
    with open(dictionary_file, 'r') as f:
        for line in f:
            word = line.strip()
            if hash_algorithm(word) == hash_value:
                print(f"[+] Password found (dictionary): {word}")
                return word
    print("[-] Not found in dictionary.")
    return None

def brute_force_attack(hash_value, hash_algorithm, charset, max_length):
    for length in range(1, max_length + 1):
        print(f"[~] Trying brute force length: {length}")
        for password_tuple in itertools.product(charset, repeat=length):
            password = ''.join(password_tuple)
            if hash_algorithm(password) == hash_value:
                print(f"[+] Password found (brute-force): {password}")
                return password
    return None

def hash_password(password, algorithm='md5'):
    return HASH_ALGORITHMS[algorithm](password.encode()).hexdigest()

def crack_password(hash_value, algorithm='md5', dictionary_file=None, charset=string.ascii_lowercase, max_length=4):
    hash_func = lambda pw: hash_password(pw, algorithm)

    if dictionary_file and os.path.exists(dictionary_file):
        print(f"[*] Trying dictionary attack from {dictionary_file}...")
        result = dictionary_attack(hash_value, hash_func, dictionary_file)
        if result:
            return result

    print("[*] Dictionary attack failed. Trying brute-force...")
    return brute_force_attack(hash_value, hash_func, charset, max_length)

if __name__ == "__main__":
    # Example: MD5 hash of "password123"
    target_hash = "482c811da5d5b4bc6d497ffa98491e38"
    algorithm = 'md5'
    dictionary_file = "dictionary.txt"
    charset = string.ascii_lowercase + string.digits
    max_length = 5  # Reduce for faster testing

    crack_password(target_hash, algorithm, dictionary_file, charset, max_length)
