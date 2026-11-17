from __future__ import annotations

import csv
import io
import os
import re
import sys
import requests
import urllib3
from bs4 import BeautifulSoup
from cripto_utils import (
    carregar_dotenv,
    criptografar_nome_arquivo,
    criptografar_texto,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
carregar_dotenv()

BASE_URL = os.environ.get("SUAP_BASE_URL", "").rstrip("/")
LOGIN_URL = os.environ.get("SUAP_LOGIN_URL") or (f"{BASE_URL}/accounts/login/" if BASE_URL else "")
USUARIO = os.environ.get("SUAP_USUARIO", "")
SENHA = os.environ.get("SUAP_SENHA", "")
CHAVE_CRIPTO = os.environ.get("SUAP_CHAVE_CRIPTO", "")


def login(session: requests.Session, usuario: str, senha: str) -> bool:
    """Faz login no SUAP e retorna True se deu certo."""
    resp = session.get(LOGIN_URL)
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, "html.parser")

    token_input = soup.find("input", {"name": "csrfmiddlewaretoken"})
    if not token_input:
        print("Não encontrei o token CSRF na página de login.", file=sys.stderr)
        return False
    csrf_token = token_input["value"]

    payload = {
        "csrfmiddlewaretoken": csrf_token,
        "username": usuario,
        "password": senha,
        "this_is_the_login_form": "1",
        "next": "",
    }
    headers = {"Referer": LOGIN_URL}

    resp = session.post(LOGIN_URL, data=payload, headers=headers)
    resp.raise_for_status()

    # Se continuarmos numa página com formulário de login, o login falhou.
    if "id_username" in resp.text or "Esqueceu ou deseja alterar sua senha" in resp.text:
        return False
    return True


def _limpar_nome_arquivo(texto: str) -> str:
    """Remove caracteres inválidos para nome de arquivo e troca espaços por _."""
    texto = re.sub(r'[<>:"/\\|?*]', "", texto)
    return re.sub(r"\s+", "_", texto.strip())


def extrair_nome_aluno(soup: BeautifulSoup, matricula: str) -> str:
    """Extrai e higieniza o nome completo do aluno da página de boletim."""
    rotulos = {"nome", "nome:", "nome civil", "nome civil:", "aluno", "aluno:"}
    nome = ""

    for tag in soup.find_all(["dt", "th"]):
        chave = " ".join(tag.get_text(strip=True).split()).lower()
        if chave in rotulos:
            irma = tag.find_next_sibling("dd" if tag.name == "dt" else "td")
            if irma:
                candidato = " ".join(irma.get_text(strip=True).split())
                if candidato:
                    nome = candidato
                    break

    if not nome:
        for h2 in soup.find_all("h2"):
            texto_h2 = " ".join(h2.get_text(strip=True).split())
            if matricula in texto_h2 or re.match(r"^aluno\s*:", texto_h2, re.IGNORECASE):
                nome = texto_h2
                break

    if not nome:
        return ""

    nome = re.sub(r"^aluno\s*:\s*", "", nome, flags=re.IGNORECASE)
    nome = re.sub(
        rf"\s*(?:\(\s*{re.escape(matricula)}\s*\)|-\s*{re.escape(matricula)})\s*$",
        "",
        nome,
    )
    return _limpar_nome_arquivo(nome)


def extrair_turma(session: requests.Session, matricula: str) -> str:
    """Busca a página principal do aluno e extrai a turma mais recente
    (tabela 'Matrículas em Períodos', última linha, coluna 'Turma')."""
    url = f"{BASE_URL}/edu/aluno/{matricula}/"
    resp = session.get(url)
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, "html.parser")

    for h3 in soup.find_all("h3"):
        if "Matrículas em Períodos" in h3.get_text(strip=True):
            box = h3.find_parent("div", class_="box") or h3.parent
            if not box:
                continue
            tabela = box.find("table")
            if not tabela or not tabela.find("tbody"):
                continue
            linhas = tabela.find("tbody").find_all("tr")
            if not linhas:
                continue
            # pega a última matrícula em período (mais recente)
            cols = linhas[-1].find_all("td")
            if len(cols) >= 3:
                turma = " ".join(cols[2].get_text(strip=True).split())
                return _limpar_nome_arquivo(turma)

    return ""


def extrair_boletim(session: requests.Session, matricula: str):
    """Busca a página de boletim e retorna (nome_aluno, lista_de_disciplinas)."""
    url = f"{BASE_URL}/edu/aluno/{matricula}/?tab=boletim"
    resp = session.get(url)
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, "html.parser")
    tabela = soup.find("table", {"summary": "Boletim do Aluno"})
    if not tabela:
        print("Não encontrei a tabela de boletim. O login pode ter falhado "
              "ou a estrutura da página mudou.", file=sys.stderr)
        return "", []

    nome_aluno = extrair_nome_aluno(soup, matricula)

    linhas = tabela.find("tbody").find_all("tr")
    disciplinas = []
    for linha in linhas:
        cols = linha.find_all("td")
        if not cols:
            continue

        def texto(td):
            return " ".join(td.get_text(strip=True).split())

        disciplina_raw = texto(cols[1])
        # remove o código do diário que vem junto no title, mantém só o nome
        disciplina = re.sub(r"\s+", " ", disciplina_raw)

        registro = {
            "diario": texto(cols[0]),
            "disciplina": disciplina,
            "carga_horaria": texto(cols[2]),
            "total_aulas": texto(cols[3]),
            "total_faltas": texto(cols[4]),
            "frequencia": texto(cols[5]),
            "situacao": texto(cols[6]),
            "n1_nota": texto(cols[7]),
            "n1_falta": texto(cols[8]),
            "media_disciplina": texto(cols[9]),
            "naf_nota": texto(cols[10]),
            "naf_falta": texto(cols[11]),
            "media_final": texto(cols[12]),
        }
        disciplinas.append(registro)

    return nome_aluno, disciplinas


def iterar_alunos():
    prefixo = USUARIO[:-2]  # mantém tudo, exceto os 2 últimos dígitos

    session = requests.Session()
    session.verify = False

    for i in range(1, 36):
        matricula = f"{prefixo}{i:02d}"

        print(f"Fazendo login como {matricula}...")
        ok = login(session, matricula, SENHA)
        if not ok:
            print("Login falhou. Verifique usuário/senha (ou captcha).", file=sys.stderr)
            sys.exit(1)

        print("Login ok. Buscando boletins...")
        print(f"\n=== Matrícula {matricula} ===")

        nome_aluno, notas = extrair_boletim(session, matricula)

        if not notas:
            print("Nenhuma nota encontrada.")
            continue

        turma = extrair_turma(session, matricula)

        if nome_aluno:
            print(f"Aluno: {nome_aluno.replace('_', ' ')}")
        if turma:
            print(f"Turma: {turma}")

        print("\n{:<40} {:<12} {:<10} {:<14}".format(
            "Disciplina", "Situação", "Freq.", "Média Final"
        ))
        print("-" * 80)
        for n in notas:
            print("{:<40} {:<12} {:<10} {:<14}".format(
                n["disciplina"][:40], n["situacao"], n["frequencia"], n["media_final"] or "-"
            ))

        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=list(notas[0].keys()))
        writer.writeheader()
        writer.writerows(notas)
        conteudo_criptografado = criptografar_texto(buffer.getvalue(), CHAVE_CRIPTO)

        out_dir = "notas"
        os.makedirs(out_dir, exist_ok=True)
        nome_parte = f"_{nome_aluno}" if nome_aluno else ""
        turma_parte = f"_{turma}" if turma else ""
        nome_logico = f"{matricula}{nome_parte}{turma_parte}_notas.csv"
        nome_criptografado = criptografar_nome_arquivo(nome_logico, CHAVE_CRIPTO)
        out_path = os.path.join(out_dir, nome_criptografado)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(conteudo_criptografado)
        print(f"Salvo (criptografado) em {out_path}")


def main():
    faltando = [
        nome
        for nome, valor in [
            ("SUAP_BASE_URL", BASE_URL),
            ("SUAP_USUARIO", USUARIO),
            ("SUAP_SENHA", SENHA),
            ("SUAP_CHAVE_CRIPTO", CHAVE_CRIPTO),
        ]
        if not valor
    ]
    if faltando:
        print(
            "Defina as variáveis de ambiente obrigatórias antes de rodar: "
            + ", ".join(faltando),
            file=sys.stderr,
        )
        sys.exit(1)

    iterar_alunos()


if __name__ == "__main__":
    main()