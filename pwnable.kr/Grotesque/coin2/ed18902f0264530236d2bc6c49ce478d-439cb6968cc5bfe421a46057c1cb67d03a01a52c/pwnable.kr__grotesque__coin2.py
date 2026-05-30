from pwn import *

io = remote("0.0.0.0", 9008)

def findCounterfeit(N, C):
    sets = []
    for pos in range(C):
        coins = [str(coin) for coin in range(N) if coin & (1 << pos)]
        if not coins:
            # empty set, send a dummy coin
            coins = ["0"]
        sets.append(" ".join(coins))

    # send C sets grouped by "-"
    line = "-".join(sets)
    io.sendline(line.encode())

    # activate the correct bits
    weights_line = io.recvline().decode().strip()
    weights = [int(w) for w in weights_line.split("-")]

    counterfeit_coin = 0
    for pos, w in enumerate(weights):
        if w % 10 != 0:
            counterfeit_coin |= (1 << pos)

    return counterfeit_coin


c = 0
inc = 0
for i in range(100):
    try:
        line = io.recvline().decode().strip()
        while not line.startswith("N="):
            line = io.recvline().decode().strip()
        N = int(line.split("N=")[1].split()[0])
        C = int(line.split("C=")[1].split()[0])
        counterfeit_coin = findCounterfeit(N, C)
        io.sendline(str(counterfeit_coin).encode())
        print(line)
    except Exception as e:
        print(f"Exception: {e}")
        exit(1)
io.interactive()
