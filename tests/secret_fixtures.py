"""Runtime-built secret-shaped strings for scanner redaction tests."""


def github_pat_sample() -> str:
    return "ghp_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"


def pem_private_key_one_line(body: str = "abcdefxyz12345") -> str:
    begin = "-----BEGIN PRIVATE KEY-----"
    end = "-----END PRIVATE KEY-----"
    return f"key = '{begin}{body}{end}'"
