from __future__ import annotations

import csv
import io
import json
import os
import re
import sys
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cripto_utils import (
    carregar_dotenv,
    criptografar_nome_arquivo,
    criptografar_texto,
    descriptografar_nome_arquivo,
    descriptografar_texto,
    esta_criptografado,
    nome_esta_criptografado,
)

carregar_dotenv()

START_MARKER = "/*__EMBEDDED_DATA_START__*/"
END_MARKER = "/*__EMBEDDED_DATA_END__*/"
CHAVE_CRIPTO = os.environ.get("SUAP_CHAVE_CRIPTO", "")
SENHA_RANKING = os.environ.get("SUAP_SENHA_RANKING") or os.environ.get("SENHA_RANKING", "")
MIN_TAMANHO_SENHA_RANKING = 12


def parse_filename(filename: str) -> tuple[str, str, str]:
    """Extrai (matricula, nome, turma) a partir do nome do arquivo CSV."""
    match = re.match(
        r"^(\d+)(?:_(.+?))??(?:_(\d{4,5}\.[0-9A-Za-z.]+))?_notas\.csv$",
        filename,
        re.IGNORECASE,
    )
    if not match:
        match = re.match(
            r"^(\d+)(?:_(.+?))??(?:_(\d{4,5}\.[0-9A-Za-z.]+))?\.csv$",
            filename,
            re.IGNORECASE,
        )
    if not match:
        stem = Path(filename).stem.replace("_", " ").strip()
        return "", stem, ""

    matricula = match.group(1)
    nome = match.group(2).replace("_", " ").strip() if match.group(2) else ""
    turma = match.group(3).strip() if match.group(3) else ""
    return matricula, nome, turma


def _descriptografar_com_fallback(
    fn, valor: str, chave_principal: str, chave_fallback: str = ""
) -> tuple[str, bool]:
    """Descriptografa com a chave principal ou faz fallback para a chave antiga."""
    try:
        return fn(valor, chave_principal), False
    except ValueError:
        if chave_fallback and chave_fallback != chave_principal:
            return fn(valor, chave_fallback), True
        raise


def _carregar_um_aluno(
    csv_path: Path, chave_cripto: str, chave_antiga_fallback: str = ""
) -> dict | None:
    """Lê, descriptografa e estrutura os dados de um único CSV."""
    conteudo = csv_path.read_text(encoding="utf-8-sig")
    precisa_chave = esta_criptografado(conteudo) or nome_esta_criptografado(csv_path.name)
    if precisa_chave and not chave_cripto:
        raise ValueError(
            "Defina a variável de ambiente SUAP_CHAVE_CRIPTO para descriptografar os CSVs."
        )

    if esta_criptografado(conteudo):
        conteudo_csv, reencrypt_conteudo = _descriptografar_com_fallback(
            descriptografar_texto, conteudo, chave_cripto, chave_antiga_fallback
        )
        conteudo_para_disco = (
            criptografar_texto(conteudo_csv, chave_cripto) if reencrypt_conteudo else conteudo
        )
    else:
        conteudo_csv = conteudo
        reencrypt_conteudo = bool(chave_cripto)
        conteudo_para_disco = (
            criptografar_texto(conteudo_csv, chave_cripto) if chave_cripto else conteudo
        )

    if nome_esta_criptografado(csv_path.name):
        nome_original, reencrypt_nome = _descriptografar_com_fallback(
            descriptografar_nome_arquivo, csv_path.name, chave_cripto, chave_antiga_fallback
        )
        novo_nome = (
            criptografar_nome_arquivo(nome_original, chave_cripto)
            if reencrypt_nome
            else csv_path.name
        )
    else:
        nome_original = csv_path.name
        reencrypt_nome = bool(chave_cripto)
        novo_nome = (
            criptografar_nome_arquivo(nome_original, chave_cripto)
            if chave_cripto
            else csv_path.name
        )

    if chave_cripto and (reencrypt_conteudo or reencrypt_nome):
        novo_caminho = csv_path.with_name(novo_nome)
        novo_caminho.write_text(conteudo_para_disco, encoding="utf-8")
        if novo_caminho != csv_path:
            csv_path.unlink()

    reader = csv.DictReader(io.StringIO(conteudo_csv))
    rows = [{k: (v or "").strip() for k, v in row.items() if k} for row in reader]

    if not rows:
        return None

    matricula, nome, turma = parse_filename(nome_original)

    return {
        "filename": nome_original,
        "matricula": matricula,
        "nome": nome,
        "turma": turma,
        "disciplinas": rows,
    }


def carregar_alunos(
    notas_dir: Path, chave_cripto: str, chave_antiga_fallback: str = ""
) -> list[dict]:
    """Lê todos os arquivos CSV da pasta notas/ (descriptografando nome e conteúdo)."""
    csv_files = sorted(notas_dir.glob("*.csv"))
    if not csv_files:
        return []

    # Processa o primeiro arquivo antes para aquecer o cache de chave de nomes
    resultados = [_carregar_um_aluno(csv_files[0], chave_cripto, chave_antiga_fallback)]
    if len(csv_files) > 1:
        with ThreadPoolExecutor() as executor:
            resultados.extend(
                executor.map(
                    lambda p: _carregar_um_aluno(p, chave_cripto, chave_antiga_fallback),
                    csv_files[1:],
                )
            )

    return [aluno for aluno in resultados if aluno is not None]


def incorporar_dados_html(
    html_path: Path,
    alunos: list[dict],
    senha_ranking: str,
    chave_cripto_arquivos: str = "",
) -> None:
    """Criptografa os dados dos alunos e incorpora no index.html."""
    if not senha_ranking:
        raise ValueError(
            "Defina a variável de ambiente SUAP_SENHA_RANKING no .env para criptografar os dados do index.html."
        )
    if len(senha_ranking) < MIN_TAMANHO_SENHA_RANKING:
        raise ValueError(
            f"A variável SUAP_SENHA_RANKING deve ter pelo menos {MIN_TAMANHO_SENHA_RANKING} caracteres no .env."
        )
    if chave_cripto_arquivos and senha_ranking == chave_cripto_arquivos:
        raise ValueError(
            "A variável SUAP_SENHA_RANKING deve ser diferente de SUAP_CHAVE_CRIPTO no .env."
        )

    html_text = html_path.read_text(encoding="utf-8")
    pattern = re.compile(
        rf"{re.escape(START_MARKER)}.*?{re.escape(END_MARKER)}",
        re.DOTALL,
    )
    if not pattern.search(html_text):
        raise ValueError("Marcadores de dados incorporados não encontrados em index.html.")

    envelope = {
        "_pad": os.urandom(32).hex(),
        "alunos": alunos,
    }
    json_payload = json.dumps(envelope, ensure_ascii=False)
    payload_criptografado = criptografar_texto(json_payload, senha_ranking)
    replacement = f"{START_MARKER}\n    window.EMBEDDED_DATA = {json.dumps(payload_criptografado)};\n    {END_MARKER}"
    updated_html = pattern.sub(lambda _: replacement, html_text, count=1)
    html_path.write_text(updated_html, encoding="utf-8")


def main() -> None:
    base_dir = Path(__file__).resolve().parent
    notas_dir = base_dir / "notas"
    html_path = base_dir / "index.html"

    if not notas_dir.is_dir():
        print(f"Pasta não encontrada: {notas_dir}", file=sys.stderr)
        sys.exit(1)

    if not html_path.is_file():
        print(f"Arquivo HTML não encontrado: {html_path}", file=sys.stderr)
        sys.exit(1)

    try:
        alunos = carregar_alunos(notas_dir, CHAVE_CRIPTO, SENHA_RANKING)
    except ValueError as exc:
        print(f"Erro ao ler/descriptografar CSVs: {exc}", file=sys.stderr)
        sys.exit(1)

    if not alunos:
        print(f"Nenhum CSV válido encontrado em: {notas_dir}", file=sys.stderr)
        sys.exit(1)

    try:
        incorporar_dados_html(html_path, alunos, SENHA_RANKING, CHAVE_CRIPTO)
    except ValueError as exc:
        print(f"Erro ao criptografar/atualizar index.html: {exc}", file=sys.stderr)
        sys.exit(1)

    total_registros = sum(len(a["disciplinas"]) for a in alunos)
    print(f"Dashboard atualizado com {len(alunos)} aluno(s) e {total_registros} registros de disciplinas.")
    print(f"Arquivo: {html_path}")
    webbrowser.open(html_path.as_uri())


if __name__ == "__main__":
    main()
