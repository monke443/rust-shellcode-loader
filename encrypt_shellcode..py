from Crypto.Cipher import AES
import sys

# AES KEY -> 16 bytes 
# IV KEY -> 16 bytes 
AES_KEY = bytes([0xB1, 0xBF, 0x4B, 0xF7, 0x6C, 0x13, 0x08, 0x82, 0xB2, 0x30, 0x2E, 0xFE, 0xB7, 0x2F, 0x34, 0xD2])
AES_IV = bytes([0xE9, 0xA7, 0xA3, 0x15, 0xF6, 0x52, 0x2A, 0x07, 0x5B, 0x25, 0xEC, 0x65, 0x9D, 0x21, 0x0E, 0x6B])

def encrypt_shellcode(input_file, output_file):
   with open(input_file, 'rb').read() as shellcode:
    cipher = AES.new(AES_KEY, AES.MODE_CFB, AES_IV, segment_size=128)
    encrypted = cipher.encrypt(shellcode)

    with open(output_file, 'wb') as f:
        f.write(encrypted)

    print(f"Encrypted shellcode written to {output_file}")

    print("const ENCRYPTED_SHELLCODE: &[u8] = &[")
    print(", ".join(f"0x{byte:02X}" for byte in encrypted))
    print("];")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python encrypt_shellcode.py <input_shellcode_file> <output_encrypted_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    encrypt_shellcode(input_file, output_file)




