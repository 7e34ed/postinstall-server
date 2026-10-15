import pytest

from apps.secrets import blob as b


def test_roundtrip():
    salt = b.new_salt()
    kek = b.derive_kek("hunter2", salt)
    data = b.empty_blob()
    data["secrets"]["a/b"] = {"value": "x"}
    enc = b.encrypt_blob(data, kek)
    dec = b.decrypt_blob(enc, kek)
    assert dec == data


def test_wrong_key_fails():
    salt = b.new_salt()
    kek = b.derive_kek("hunter2", salt)
    enc = b.encrypt_blob({"x": 1}, kek)
    kek2 = b.derive_kek("hunter3", salt)
    with pytest.raises(b.BlobError, match="decrypt failed"):
        b.decrypt_blob(enc, kek2)


def test_empty_master_key():
    with pytest.raises(b.BlobError):
        b.derive_kek("", b.new_salt())


def test_salt_wrong_size():
    with pytest.raises(b.BlobError):
        b.derive_kek("x", b"\x00" * 8)


def test_corrupted_blob():
    salt = b.new_salt()
    kek = b.derive_kek("k", salt)
    enc = b.encrypt_blob({"x": 1}, kek)
    corrupted = enc[:-1] + bytes([enc[-1] ^ 0xFF])
    with pytest.raises(b.BlobError):
        b.decrypt_blob(corrupted, kek)


def test_argon2_params_respected():
    salt = b.new_salt()
    p = b.Argon2Params(time_cost=1, memory_cost=8 * 1024, parallelism=1)
    k1 = b.derive_kek("k", salt, p)
    k2 = b.derive_kek("k", salt, p)
    assert k1 == k2
    assert len(k1) == 32