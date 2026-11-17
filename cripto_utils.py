from __future__ import annotations

import base64
import hashlib
import hmac
import os
from functools import lru_cache
from pathlib import Path

PREFIXO_ENC = "ENC1:"
PREFIXO_NOME_ENC = "encf_"
SALT_NOME_DOMINIO = b"suap-filename-v1"
ITERACOES_PBKDF2 = 600_000


def carregar_dotenv(caminho_env: Path | None = None) -> None:
    """Carrega variáveis de ambiente do arquivo .env se ele existir."""
    arquivo = caminho_env or (Path(__file__).resolve().parent / ".env")
    if not arquivo.is_file():
        return

    for linha in arquivo.read_text(encoding="utf-8-sig").splitlines():
        linha = linha.strip()
        if not linha or linha.startswith("#") or "=" not in linha:
            continue
        if linha.startswith("export "):
            linha = linha[7:].lstrip()
        chave, valor = linha.split("=", 1)
        chave = chave.strip()
        valor = valor.strip()
        if len(valor) >= 2 and valor[0] == valor[-1] and valor[0] in {"'", '"'}:
            valor = valor[1:-1]
        if chave:
            os.environ.setdefault(chave, valor)


@lru_cache(maxsize=256)
def _derivar_chaves(chave: str, salt: bytes) -> tuple[bytes, bytes]:
    """Deriva chaves de criptografia e autenticação (HMAC) a partir da senha."""
    material = hashlib.pbkdf2_hmac(
        "sha256",
        chave.encode("utf-8"),
        salt,
        ITERACOES_PBKDF2,
        dklen=64,
    )
    return material[:32], material[32:]


def _xor_keystream(dados: bytes, enc_key: bytes, salt: bytes) -> bytes:
    """Gera keystream determinístico via SHA-256 em blocos de 32 bytes e aplica XOR."""
    blocos = []
    total_blocos = (len(dados) + 31) // 32
    for counter in range(total_blocos):
        blocos.append(
            hashlib.sha256(enc_key + salt + counter.to_bytes(8, "big")).digest()
        )
    keystream = b"".join(blocos)
    return bytes(b ^ k for b, k in zip(dados, keystream))


def esta_criptografado(conteudo: str) -> bool:
    """Verifica se o texto possui o cabeçalho de conteúdo criptografado."""
    return conteudo.startswith(PREFIXO_ENC)


def criptografar_texto(texto: str, chave: str) -> str:
    """Criptografa texto UTF-8 usando PBKDF2 + stream SHA-256 + HMAC-SHA256."""
    if not chave:
        raise ValueError("A chave de criptografia não pode ser vazia.")

    salt = os.urandom(16)
    enc_key, mac_key = _derivar_chaves(chave, salt)
    cifrado = _xor_keystream(texto.encode("utf-8"), enc_key, salt)
    mac = hmac.new(mac_key, salt + cifrado, hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(salt + mac + cifrado).decode("ascii")
    return f"{PREFIXO_ENC}{token}"


def descriptografar_texto(conteudo: str, chave: str) -> str:
    """Valida a integridade via HMAC e descriptografa o texto original."""
    if not chave:
        raise ValueError("A chave de criptografia não pode ser vazia.")
    if not esta_criptografado(conteudo):
        raise ValueError("Conteúdo não está no formato criptografado esperado.")

    payload_b64 = conteudo[len(PREFIXO_ENC):].strip()
    try:
        bruto = base64.urlsafe_b64decode(payload_b64.encode("ascii"))
    except Exception as exc:
        raise ValueError("Chave de criptografia inválida ou arquivo corrompido.") from exc

    if len(bruto) < 48:
        raise ValueError("Chave de criptografia inválida ou arquivo corrompido.")

    salt = bruto[:16]
    mac_recebido = bruto[16:48]
    cifrado = bruto[48:]

    enc_key, mac_key = _derivar_chaves(chave, salt)
    mac_esperado = hmac.new(mac_key, salt + cifrado, hashlib.sha256).digest()
    if not hmac.compare_digest(mac_recebido, mac_esperado):
        raise ValueError("Chave de criptografia inválida ou arquivo corrompido.")

    try:
        return _xor_keystream(cifrado, enc_key, salt).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Chave de criptografia inválida ou arquivo corrompido.") from exc


def nome_esta_criptografado(nome_arquivo: str) -> bool:
    """Verifica se o nome do arquivo CSV está no formato criptografado."""
    lower = nome_arquivo.lower()
    return lower.startswith(PREFIXO_NOME_ENC) and lower.endswith(".csv")


def criptografar_nome_arquivo(nome_arquivo: str, chave: str) -> str:
    """Criptografa o nome do arquivo CSV de forma determinística e compatível com Windows."""
    if not chave:
        raise ValueError("A chave de criptografia não pode ser vazia.")
    if nome_esta_criptografado(nome_arquivo):
        return nome_arquivo

    stem = nome_arquivo[:-4] if nome_arquivo.lower().endswith(".csv") else nome_arquivo
    dados = stem.encode("utf-8")

    enc_key, mac_key = _derivar_chaves(chave, SALT_NOME_DOMINIO)
    siv = hmac.new(mac_key, dados, hashlib.sha256).digest()[:16]
    cifrado = _xor_keystream(dados, enc_key, siv)
    token = base64.b32encode(siv + cifrado).decode("ascii").lower().rstrip("=")
    return f"{PREFIXO_NOME_ENC}{token}.csv"


def descriptografar_nome_arquivo(nome_arquivo: str, chave: str) -> str:
    """Valida e descriptografa um nome de arquivo CSV criptografado."""
    if not chave:
        raise ValueError("A chave de criptografia não pode ser vazia.")
    if not nome_esta_criptografado(nome_arquivo):
        return nome_arquivo

    token = nome_arquivo[len(PREFIXO_NOME_ENC):-4]
    faltando = (-len(token)) % 8
    token_padded = token.upper() + ("=" * faltando)

    try:
        bruto = base64.b32decode(token_padded.encode("ascii"), casefold=True)
    except Exception as exc:
        raise ValueError("Chave de criptografia inválida ou nome de arquivo corrompido.") from exc

    if len(bruto) < 16:
        raise ValueError("Chave de criptografia inválida ou nome de arquivo corrompido.")

    siv = bruto[:16]
    cifrado = bruto[16:]

    enc_key, mac_key = _derivar_chaves(chave, SALT_NOME_DOMINIO)
    dados = _xor_keystream(cifrado, enc_key, siv)
    siv_esperado = hmac.new(mac_key, dados, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(siv, siv_esperado):
        raise ValueError("Chave de criptografia inválida ou nome de arquivo corrompido.")

    try:
        return f"{dados.decode('utf-8')}.csv"
    except UnicodeDecodeError as exc:
        raise ValueError("Chave de criptografia inválida ou nome de arquivo corrompido.") from exc

