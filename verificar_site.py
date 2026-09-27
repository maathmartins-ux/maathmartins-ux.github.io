"""Trava do site publico: nada pessoal ou secreto entra no repositorio, e as paginas nao
abrem superficie de ataque. Roda nos hooks (.githooks/) e nos testes.

Uso:  .venv/Scripts/python.exe verificar_site.py              confere a arvore de trabalho
      .venv/Scripts/python.exe verificar_site.py --staged     confere o que vai no commit
      .venv/Scripts/python.exe verificar_site.py --mensagem F confere a mensagem de commit
      .venv/Scripts/python.exe verificar_site.py --pre-push   confere os commits que vao sair
                                                              (le as refs da entrada padrao)

Por que existe: este repositorio e PUBLICO. Segredo ou e-mail commitado nao some com
`rm` - fica no historico e em qualquer copia (fork, cache, arquivo da web).

A lista de termos pessoais (nome, e-mail, usuario do PC...) fica FORA do repositorio,
em ~/.segredos/choque-sinaptico-site/lista_pessoal.txt (ou SITE_LISTA_PESSOAL):
publicar a lista seria o proprio vazamento.
"""
import html
import os
import re
import subprocess
import sys
import unicodedata
import urllib.parse
from html.parser import HTMLParser
from pathlib import Path

RAIZ = Path(__file__).resolve().parent
LOGIN = "maathmartins-ux"
LISTA_PESSOAL_PADRAO = Path.home() / ".segredos" / "choque-sinaptico-site" / "lista_pessoal.txt"
ZERO = "0" * 40

# --- o que pode existir no repositorio (lista branca: arquivo novo exige editar aqui) -----
LISTA_BRANCA = re.compile(
    r"^(docs/[a-z0-9_-]+\.(html|css)|docs/\.nojekyll|tests/test_[a-z0-9_]+\.py"
    r"|\.githooks/(pre-commit|pre-push|commit-msg)"
    r"|\.gitignore|\.gitattributes|README\.md|pytest\.ini|verificar_site\.py)$")

# --- identidade de commit: so a noreply do GitHub ------------------------------------------
IDENTIDADE_OK = re.compile(r"^\d+\+[\w-]+@users\.noreply\.github\.com$")
EMAIL_PERMITIDO = re.compile(r"^(\d+\+[\w-]+@users\.noreply\.github\.com|noreply@anthropic\.com)$", re.I)

# --- vazamentos (procurados no texto ja normalizado) ---------------------------------------
VAZAMENTOS = {
    "e-mail": re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)*\.[a-z]{2,}", re.I),
    "chave de API do Google": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "segredo de cliente OAuth do Google": re.compile(r"GOCSPX-[0-9A-Za-z_-]{10,}"),
    "token OAuth do Google": re.compile(r"\bya29\.[0-9A-Za-z_-]{20,}|\b1//0[0-9A-Za-z_-]{20,}"),
    "ID de cliente OAuth do Google": re.compile(r"\b\d{6,}-[0-9a-z]{32}\.apps\.googleusercontent\.com"),
    "token do GitHub": re.compile(r"\b(gh[pousr]_[0-9A-Za-z]{30,}|github_pat_[0-9A-Za-z_]{30,})"),
    "chave de API (sk-)": re.compile(r"\bsk-(ant-)?[0-9A-Za-z_-]{20,}"),
    "token de bot do Telegram": re.compile(r"\b\d{8,10}:[0-9A-Za-z_-]{35}\b"),
    "chave privada": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY( BLOCK)?-----"),
    "campo de credencial": re.compile(
        r"(client_secret|refresh_token|access_token|api_?key|password|senha)[\"']?\s*[:=]", re.I),
    "CPF": re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"),
    "caminho do computador": re.compile(
        # literais partidos ("Use" "rs") para a regex nao casar com o proprio codigo-fonte
        r"\b[A-Z]:[\\/]+Users[\\/]|/(mnt/)?[a-z]/Use" r"rs/[^/\s\"'<>]+|/(Users|home)/[^/\s\"'<>]+"
        r"|%USER" r"PROFILE%|\\\\[\w.-]+\\[\w$.-]+", re.I),
    "telefone": re.compile(r"\(?\b\d{2}\)?[ .-]?9\d{4}[ .-]?\d{4}\b|\+55[ .-]?\d{10,11}\b"),
}
CPF_SEM_PONTOS = re.compile(r"(?<!\d)\d{11}(?!\d)")          # so dentro de docs/ (vai ao ar)

# --- HTML: politica de seguranca exigida em toda pagina ------------------------------------
CSP_EXATA = "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'"
TAGS_PROIBIDAS = {"script", "form", "iframe", "frame", "frameset", "object", "embed", "applet",
                  "base", "style"}
TAGS_DE_RECURSO = {"img", "source", "video", "audio", "track", "link", "input", "picture"}
ATRIBUTOS_URL = {"href", "src", "srcset", "action", "formaction", "poster", "data", "cite", "background"}


def normalizar(texto):
    """Desfaz os disfarces comuns: entidades HTML, %40 de URL e caracteres de largura cheia."""
    return unicodedata.normalize("NFKC", urllib.parse.unquote(html.unescape(texto)))


def carregar_lista_pessoal(caminho=None):
    """Termos pessoais, um por linha (# comenta). Arquivo ausente: lista vazia."""
    caminho = Path(caminho or os.environ.get("SITE_LISTA_PESSOAL", LISTA_PESSOAL_PADRAO))
    if not caminho.exists():
        return []
    linhas = caminho.read_text(encoding="utf-8").splitlines()
    return [s.strip() for s in linhas if s.strip() and not s.strip().startswith("#")]


def problemas_de_nome(caminho):
    """So o que esta na lista branca pode existir neste repositorio publico."""
    if LISTA_BRANCA.match(caminho):
        return []
    return [f"{caminho}: arquivo fora da lista branca do repositorio publico (ver LISTA_BRANCA)"]


def _vazamentos(texto, termos=()):
    """[(linha, descricao)] de tudo o que parece dado pessoal ou segredo."""
    norm = normalizar(texto)
    achados = []
    for nome, padrao in VAZAMENTOS.items():
        for m in padrao.finditer(norm):
            if nome == "e-mail" and EMAIL_PERMITIDO.match(m.group(0)):
                continue
            achados.append((norm.count("\n", 0, m.start()) + 1, f"possivel {nome}"))
    for termo in termos:
        for m in re.finditer(r"(?<!\w)" + re.escape(termo) + r"(?!\w)", norm, re.I):
            achados.append((norm.count("\n", 0, m.start()) + 1, f"termo pessoal da lista local ({termo})"))
    return norm, achados


def problemas_de_conteudo(caminho, dados, termos=()):
    """Vazamento de dado pessoal ou segredo em qualquer arquivo do repositorio."""
    if b"\x00" in dados:
        return [f"{caminho}: arquivo binario nao previsto"]
    norm, achados = _vazamentos(dados.decode("utf-8", errors="replace"), termos)
    if caminho.startswith("docs/"):
        achados += [(norm.count("\n", 0, m.start()) + 1, "possivel CPF")
                    for m in CPF_SEM_PONTOS.finditer(norm)]
    return [f"{caminho}:{linha}: {desc}" for linha, desc in achados]


def problemas_de_mensagem(texto, termos=()):
    """Mensagem de commit tambem e publica: mesmos padroes, sem as linhas de comentario."""
    corpo = "\n".join(s for s in texto.splitlines() if not s.startswith("#"))
    return [f"mensagem de commit (linha {linha}): {desc}" for linha, desc in _vazamentos(corpo, termos)[1]]


class _LeitorHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.no_head = False
        self.csp, self.referrer, self.erros = [], [], []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "head":
            self.no_head = True
        if tag in TAGS_PROIBIDAS:
            self.erros.append(f"tag <{tag}> proibida")
        if tag == "meta":
            equiv = a.get("http-equiv", "").lower()
            if equiv == "content-security-policy":
                self.csp.append((self.no_head, a.get("content", "")))
            elif equiv == "refresh":
                self.erros.append("meta refresh proibido (redireciona sem o usuario pedir)")
            if a.get("name", "").lower() == "referrer":
                self.referrer.append((self.no_head, a.get("content", "")))
        for k, v in a.items():
            if k.startswith("on"):
                self.erros.append(f"atributo de evento {k}= proibido")
            if k == "style":
                self.erros.append("atributo style= proibido (estilo so no estilo.css)")
            if k == "target":
                self.erros.append("atributo target= proibido")
            if k not in ATRIBUTOS_URL:
                continue
            url = v.strip().lower()
            esquema = url.split(":", 1)[0]
            if esquema in ("javascript", "data", "vbscript") and ":" in url:
                self.erros.append(f"link {esquema}: proibido")
            elif tag in TAGS_DE_RECURSO and url.startswith(("http://", "https://", "//")):
                self.erros.append(f"recurso externo em <{tag} {k}=> (vazaria o IP do visitante)")
            elif url.startswith(("http://", "//")):
                self.erros.append(f"link sem https em <{tag} {k}=>")

    def handle_endtag(self, tag):
        if tag == "head":
            self.no_head = False


def problemas_de_html(caminho, texto):
    """Pagina do site sem as protecoes: CSP exata no head, no-referrer, nada ativo ou externo."""
    if not (caminho.startswith("docs/") and caminho.endswith(".html")):
        return []
    leitor = _LeitorHTML()
    leitor.feed(texto)
    leitor.close()
    erros = [f"{caminho}: {e}" for e in leitor.erros]
    if leitor.csp != [(True, CSP_EXATA)]:
        erros.append(f"{caminho}: precisa de exatamente uma meta Content-Security-Policy no <head> "
                     f"com o valor exato: {CSP_EXATA}")
    if leitor.referrer != [(True, "no-referrer")]:
        erros.append(f'{caminho}: precisa de exatamente um <meta name="referrer" content="no-referrer"> no <head>')
    return erros


def _ident(ident):
    m = re.match(r"^(.*?) <([^>]*)>", ident.strip())
    return (m.group(1), m.group(2)) if m else ("", "")


def problemas_de_identidade(autor, committer):
    """Autor E committer: nome = login publico, e-mail = noreply do GitHub. Nunca o pessoal."""
    erros = []
    for papel, ident in (("autor", autor), ("committer", committer)):
        nome, email = _ident(ident)
        if nome != LOGIN or not IDENTIDADE_OK.match(email):
            erros.append(f"identidade do {papel} precisa ser '{LOGIN} <id+login noreply do GitHub>'")
    return erros


def _git(*args, raiz=RAIZ, texto=True):
    r = subprocess.run(["git", *args], cwd=raiz, capture_output=True, check=True)
    return r.stdout.decode("utf-8", errors="replace") if texto else r.stdout


def arquivos(staged):
    if staged:
        saida = _git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
    else:
        saida = _git("ls-files", "-z", "--cached", "--others", "--exclude-standard")
    return sorted({p for p in saida.split("\0") if p})


def _problemas_do_arquivo(caminho, dados, termos):
    return (problemas_de_nome(caminho) + problemas_de_conteudo(caminho, dados, termos)
            + problemas_de_html(caminho, dados.decode("utf-8", errors="replace")))


def problemas_dos_commits(shas, raiz=RAIZ, termos=()):
    """Cada commit que vai sair: autor, committer, mensagem e cada arquivo alterado."""
    erros = []
    for sha in shas:
        an, ae, cn, ce, corpo = _git("log", "-1", "--format=%an%x00%ae%x00%cn%x00%ce%x00%B", sha,
                                     raiz=raiz).split("\0", 4)
        prefixo = f"commit {sha[:7]}: "
        erros += [prefixo + e for e in problemas_de_identidade(f"{an} <{ae}>", f"{cn} <{ce}>")]
        erros += [prefixo + e for e in problemas_de_mensagem(corpo, termos)]
        nomes = _git("diff-tree", "--no-commit-id", "--root", "-r", "--name-only", "--diff-filter=ACMR",
                     "-z", sha, raiz=raiz)
        for caminho in (p for p in nomes.split("\0") if p):
            dados = _git("show", f"{sha}:{caminho}", raiz=raiz, texto=False)
            erros += [prefixo + e for e in _problemas_do_arquivo(caminho, dados, termos)]
    return erros


def commits_do_push(linhas, raiz=RAIZ):
    """Commits novos a partir das linhas '<ref local> <sha local> <ref remota> <sha remoto>'."""
    shas = []
    for linha in linhas:
        partes = linha.split()
        if len(partes) != 4 or partes[1] == ZERO:
            continue
        local, remoto = partes[1], partes[3]
        faixa = [local, "--not", "--remotes"] if remoto == ZERO else [f"{remoto}..{local}"]
        shas += _git("rev-list", *faixa, raiz=raiz).split()
    return list(dict.fromkeys(shas))


def verificar(staged=False, termos=None):
    termos = carregar_lista_pessoal() if termos is None else termos
    erros = problemas_de_identidade(_git("var", "GIT_AUTHOR_IDENT"), _git("var", "GIT_COMMITTER_IDENT"))
    for caminho in arquivos(staged):
        if not staged and not (RAIZ / caminho).exists():
            continue
        dados = _git("show", f":{caminho}", texto=False) if staged else (RAIZ / caminho).read_bytes()
        erros += _problemas_do_arquivo(caminho, dados, termos)
    return erros


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    termos = carregar_lista_pessoal()
    if not termos:
        print("AVISO: lista pessoal ausente ou vazia; a trava nao confere nome/usuario/empregador.")
    if "--mensagem" in argv:
        arq = argv[argv.index("--mensagem") + 1]
        erros = problemas_de_mensagem(Path(arq).read_text(encoding="utf-8", errors="replace"), termos)
    elif "--pre-push" in argv:
        erros = problemas_dos_commits(commits_do_push(sys.stdin.read().splitlines()), termos=termos)
    else:
        erros = verificar(staged="--staged" in argv, termos=termos)
    for e in erros:
        print("BARRADO:", e)
    print("verificar_site:", "REPROVADO" if erros else "ok")
    return 1 if erros else 0


if __name__ == "__main__":
    sys.exit(main())
