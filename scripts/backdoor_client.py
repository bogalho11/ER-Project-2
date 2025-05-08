import socket

def encrypt(command: str, command_len: int):
    encrypted = [0] * command_len
    pow_res = pow(command_len, command_len) & 255
    for i in range(command_len):
        encrypted[i] = ord(command[i]) ^ (pow_res + i)

    return bytearray(encrypted)

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', 1337))

    try:
        while True:
            command = input("Command to run: ").strip()
            s.sendall(encrypt(f"c {command}", len(command) + 2))
    except:
        pass

    s.close()

if __name__ == '__main__':
    main()
