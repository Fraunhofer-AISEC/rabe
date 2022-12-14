from rabe_py import lsw


def run_lsw():
    (pk, msk) = lsw.setup()
    plaintext = "our plaintext!"
    policy = '"A" or "B"'
    ciphertext = lsw.encrypt(pk, ["A", "B"], plaintext)
    sk = lsw.keygen(pk, msk, policy)
    plaintext_after = lsw.decrypt(sk, ciphertext)

    print("".join(chr(i) for i in plaintext_after))

run_lsw()