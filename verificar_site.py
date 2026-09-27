"""Trava do site publico: nada pessoal ou secreto entra no repositorio, e as paginas nao
abrem superficie de ataque. Roda no pre-commit (.githooks/pre-commit) e nos testes.

Uso:  .venv/Scripts/python.exe verificar_site.py            confere a arvore de trabalho
      .venv/Scripts/python.exe verificar_site.py --staged   confere o que vai no commit

Por que existe: este repositorio e PUBLICO. Segredo ou e-mail commitado nao some com
`rm` - fica no historico e em qualquer copia (fork, cache, arquivo da web).
"""
import re
import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent
SITE = "docs/"                                   # so esta pasta vai ao ar no GitHub Pages
EXTENSOES_DO_SITE = {".html", ".css"}            # mais o .nojekyll (sem extensao)
IDENTIDADE_OK = re.compile(r"^\d+\+[\w-]+@users\.noreply\.github\.com$")

VAZAMENTOS = {
    "e-mail": re.compile(r"[\w.+-]+@[\w-]+\.[a-z]{2,}", re.I),
    "chave de API do Google": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "segredo de cliente OAuth do Google": re.compile(r"GOCSPX-[0-9A-Za-z_-]{10,}"),
    "token do GitHub": re.compile(r"\b(gh[pousr]_[0-9A-Za-z]{30,}|github_pat_[0-9A-Za-z_]{30,})"),
    "chave de API (sk-)": re.compile(r"\bsk-(ant-)?[0-9A-Za-z_-]{20,}"),
    "token de bot do Telegram": re.compile(r"\b\d{8,10}:[0-9A-Za-z_-]{35}\b"),
    "chave privada": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "campo de credencial": re.compile(
        r"(client_secret|refresh_token|access_token|api_?key|password|senha)[\"']?\s*[:=]", re.I),
    "CPF": re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"),
    "caminho do computador": re.compile(r"\b[A-Z]:[\\/]+Users[\\/]|/(Users|home)/[a-z]", re.I),
    "telefone": re.compile(r"\(?\b\d{2}\)?[ .-]?9\d{4}[ .-]?\d{4}\b"),
}
NOMES_PROIBIDOS = re.compile(
    r"(^|/)(\.env[^/]*|[^/]*\.(json|pem|key|p12|pfx|sqlite3?|db|log)|[^/]*(secret|token|senha|credencia)[^/]*)$",
    re.I)
HTML_PROIBIDO = {
    "script": re.compile(r"<script", re.I),
    "formulario": re.compile(r"<form", re.I),
    "iframe/object/embed": re.compile(r"<(iframe|object|embed)", re.I),
    "evento inline (onclick=...)": re.compile(r"\son[a-z]+\s*=", re.I),
    "link javascript:": re.compile(r"javascript:", re.I),
    "link sem https": re.compile(r"(href|src)\s*=\s*[\"']http://", re.I),
}
CSP = "default-src 'none'"
REFERRER = '<meta name="referrer" content="no-referrer">'


def problemas_de_nome(caminho):
    """Arquivo que nao deveria existir num repositorio publico, ou fora do previsto no site."""
    erros = []
    if NOMES_PROIBIDOS.search(caminho):
        erros.append(f"{caminho}: tipo de arquivo proibido num repositorio publico")
    if caminho.startswith(SITE):
        nome = caminho.rsplit("/", 1)[-1]
        if nome != ".nojekyll" and Path(nome).suffix.lower() not in EXTENSOES_DO_SITE:
            erros.append(f"{caminho}: o site so publica .html e .css")
    return erros


def problemas_de_conteudo(caminho, dados):
    """Vazamento de dado pessoal ou segredo em qualquer arquivo do repositorio."""
    if b"\x00" in dados:
        return [f"{caminho}: arquivo binario nao previsto"]
    texto = dados.decode("utf-8", errors="replace")
    erros = []
    for nome, padrao in VAZAMENTOS.items():
        for m in padrao.finditer(texto):
            linha = texto.count("\n", 0, m.start()) + 1
            erros.append(f"{caminho}:{linha}: possivel {nome}")
    return erros


def problemas_de_html(caminho, texto):
    """Pagina do site sem as protecoes: CSP, sem referrer, sem script nem formulario."""
    if not (caminho.startswith(SITE) and caminho.endswith(".html")):
        return []
    erros = [f"{caminho}: contem {nome}" for nome, p in HTML_PROIBIDO.items() if p.search(texto)]
    if CSP not in texto:
        erros.append(f"{caminho}: falta a Content-Security-Policy ({CSP})")
    if REFERRER not in texto:
        erros.append(f"{caminho}: falta {REFERRER}")
    return erros


def problema_de_identidade(email):
    """Commit neste repositorio so com o e-mail noreply do GitHub, nunca o pessoal."""
    if IDENTIDADE_OK.match(email or ""):
        return []
    return ["identidade do git: use o e-mail noreply do GitHub neste repositorio "
            "(git config user.email <id>+<login>@users.noreply.github.com)"]


def _git(*args):
    return subprocess.run(["git", *args], cwd=RAIZ, capture_output=True, check=True).stdout


def arquivos(staged):
    if staged:
        saida = _git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
    else:
        saida = _git("ls-files", "-z", "--cached", "--others", "--exclude-standard")
    return sorted({p for p in saida.decode("utf-8").split("\0") if p})


def ler(caminho, staged):
    return _git("show", f":{caminho}") if staged else (RAIZ / caminho).read_bytes()


def verificar(staged=False):
    erros = problema_de_identidade(_git("config", "user.email").decode().strip())
    for caminho in arquivos(staged):
        if not staged and not (RAIZ / caminho).exists():
            continue
        dados = ler(caminho, staged)
        erros += problemas_de_nome(caminho)
        erros += problemas_de_conteudo(caminho, dados)
        erros += problemas_de_html(caminho, dados.decode("utf-8", errors="replace"))
    return erros


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    erros = verificar(staged="--staged" in argv)
    for e in erros:
        print("BARRADO:", e)
    print("verificar_site:", "REPROVADO" if erros else "ok")
    return 1 if erros else 0


if __name__ == "__main__":
    sys.exit(main())
