"""A trava pega o que vazaria num repositorio publico e aprova o site real.

Os exemplos ruins sao montados em tempo de execucao (concatenacao) para que este
arquivo, que tambem e publico, nao contenha nenhum dado com cara de verdadeiro.
"""
import subprocess

import pytest

import verificar_site as V

ARROBA = "@"
NOREPLY = "123+login" + ARROBA + "users.noreply.github.com"
CABECA = (
    '<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">'
    f'<meta http-equiv="Content-Security-Policy" content="{V.CSP_EXATA}">'
    '<meta name="referrer" content="no-referrer"><title>T</title>'
    '<link rel="stylesheet" href="estilo.css"></head>'
)
PAGINA_OK = CABECA + '<body><a href="https://exemplo.org/">x</a></body></html>'


def html(corpo="", cabeca=CABECA):
    return cabeca + f"<body>{corpo}</body></html>"


# --- vazamento de dado pessoal ou segredo -------------------------------------------------

@pytest.mark.parametrize("vazamento, tipo", [
    ("contato: fulano" + ARROBA + "exemplo.com", "e-mail"),
    ("fulano&" + "#64;exemplo.com", "e-mail"),
    ("fulano&" + "#x40;exemplo.com", "e-mail"),
    ("fulano&" + "commat;exemplo.com", "e-mail"),
    ("mailto:fulano%" + "40exemplo.com", "e-mail"),
    ("fulano" + chr(0xFF20) + "exemplo.com", "e-mail"),
    ("AIza" + "B" * 35, "chave de API do Google"),
    ("GOCSPX-" + "a1b2c3d4e5f6", "segredo de cliente OAuth do Google"),
    ("ya29." + "c" * 40, "token OAuth do Google"),
    ("1//0" + "d" * 40, "token OAuth do Google"),
    ("123456789012-" + "a" * 32 + ".apps.googleusercontent.com", "ID de cliente OAuth do Google"),
    ("ghp_" + "x" * 36, "token do GitHub"),
    ("sk-ant-" + "y" * 30, "chave de API (sk-)"),
    ("123456789:" + "A" * 35, "token de bot do Telegram"),
    ("-----BEGIN " + "RSA PRIVATE KEY-----", "chave privada"),
    ("-----BEGIN " + "PGP PRIVATE KEY BLOCK-----", "chave privada"),
    ('"client_' + 'secret": "abc"', "campo de credencial"),
    ("123.456.789-" + "09", "CPF"),
    ("C:" + "\\Users\\alguem\\arquivo", "caminho do computador"),
    ("/c/" + "Users/12345/Desktop", "caminho do computador"),
    ("/mnt/c/" + "Users/12345", "caminho do computador"),
    ("%USER" + "PROFILE%\\x", "caminho do computador"),
    ("(11) 9" + "8765-4321", "telefone"),
    ("+55" + "119876" + "54321", "telefone"),
])
def test_vazamento_e_barrado(vazamento, tipo):
    erros = V.problemas_de_conteudo("docs/x.html", f"<p>{vazamento}</p>".encode())
    assert any(tipo in e for e in erros), erros


def test_cpf_sem_pontuacao_so_conta_no_site():
    cpf = "123456789" + "09"
    assert any("CPF" in e for e in V.problemas_de_conteudo("docs/x.html", cpf.encode()))


def test_links_publicos_e_noreply_nao_sao_vazamento():
    texto = ('<a href="https://www.youtube.com/' + ARROBA + 'choquesinaptico2760">canal</a>'
             '<a href="https://myaccount.google.com/permissions">x</a> ' + NOREPLY +
             " noreply" + ARROBA + "anthropic.com")
    assert V.problemas_de_conteudo("docs/index.html", texto.encode()) == []


def test_lista_pessoal_fora_do_repositorio_e_aplicada(tmp_path):
    lista = tmp_path / "lista.txt"
    lista.write_text("# termos\nFulano\nEmpresaX\n", encoding="utf-8")
    termos = V.carregar_lista_pessoal(lista)
    assert termos == ["Fulano", "EmpresaX"]
    erros = V.problemas_de_conteudo("README.md", b"feito por fulano na empresax", termos)
    assert len([e for e in erros if "termo pessoal" in e]) == 2


def test_lista_pessoal_casa_palavra_inteira(tmp_path):
    # o login publico contem pedacos de nome; so a palavra inteira conta
    erros = V.problemas_de_conteudo("docs/x.html", b"https://fulanoxyz-ux.github.io/", ["xyz"])
    assert erros == []


def test_lista_pessoal_ausente_devolve_vazia(tmp_path):
    assert V.carregar_lista_pessoal(tmp_path / "nao_existe.txt") == []


def test_binario_e_barrado():
    assert V.problemas_de_conteudo("docs/logo.png", b"\x89PNG\x00\x00")


# --- nomes de arquivo: lista branca -------------------------------------------------------

@pytest.mark.parametrize("caminho", [
    ".env", "config/.env.local", "dados.json", "chave.pem", "client_secret_123.json",
    "youtube_token.txt", "banco.sqlite3", "saida.log", "notas.txt", "docs/app.js",
    "docs/foto.png", "docs/sub/pagina.html", "scripts/deploy.py",
])
def test_arquivo_fora_da_lista_branca_e_barrado(caminho):
    assert V.problemas_de_nome(caminho)


@pytest.mark.parametrize("caminho", [
    "docs/index.html", "docs/privacidade.html", "docs/estilo.css", "docs/.nojekyll",
    "README.md", ".gitignore", ".gitattributes", "pytest.ini", "verificar_site.py",
    "tests/test_verificar_site.py", ".githooks/pre-commit", ".githooks/pre-push",
    ".githooks/commit-msg",
])
def test_arquivo_da_lista_branca_passa(caminho):
    assert V.problemas_de_nome(caminho) == []


# --- HTML: lido com parser, nao por substring ---------------------------------------------

def test_pagina_protegida_passa():
    assert V.problemas_de_html("docs/index.html", PAGINA_OK) == []


@pytest.mark.parametrize("corpo, motivo", [
    ("<script>alert(1)</script>", "script"),
    ('<form action="https://x.org">', "form"),
    ('<iframe src="https://x.org">', "iframe"),
    ('<img src="a.png" onerror="x()">', "evento"),
    ('<a href="javascript:x()">x</a>', "javascript:"),
    ('<a href="http://x.org">x</a>', "sem https"),
    ('<img src="https://rastreador.exemplo/p.gif">', "recurso externo"),
    ('<img src="//rastreador.exemplo/p.gif">', "recurso externo"),
    ('<a href="//x.org">x</a>', "sem https"),
    ('<base href="https://x.org/">', "base"),
    ("<style>body{}</style>", "style"),
    ('<p style="color:red">x</p>', "style"),
    ('<a href="https://x.org" target="_blank">x</a>', "target"),
])
def test_superficie_de_ataque_e_barrada(corpo, motivo):
    assert any(motivo in e for e in V.problemas_de_html("docs/index.html", html(corpo)))


def test_refresh_e_css_externo_sao_barrados():
    cabeca = CABECA.replace("</head>", '<meta http-equiv="refresh" content="0;url=https://x.org/">'
                            '<link rel="stylesheet" href="https://cdn.exemplo/x.css"></head>')
    erros = V.problemas_de_html("docs/index.html", html(cabeca=cabeca))
    assert any("refresh" in e for e in erros)
    assert any("recurso externo" in e for e in erros)


def test_csp_so_em_comentario_e_barrada():
    cabeca = CABECA.replace(f'<meta http-equiv="Content-Security-Policy" content="{V.CSP_EXATA}">',
                            f"<!-- {V.CSP_EXATA} -->")
    assert any("Content-Security-Policy" in e for e in V.problemas_de_html("docs/i.html", html(cabeca=cabeca)))


def test_csp_afrouxada_e_barrada():
    cabeca = CABECA.replace("img-src 'self'", "img-src *")
    assert any("Content-Security-Policy" in e for e in V.problemas_de_html("docs/i.html", html(cabeca=cabeca)))


def test_csp_duplicada_ou_fora_do_head_e_barrada():
    meta = f'<meta http-equiv="Content-Security-Policy" content="{V.CSP_EXATA}">'
    dup = CABECA.replace("</head>", meta + "</head>")
    fora = CABECA.replace(meta, "")
    assert any("Content-Security-Policy" in e for e in V.problemas_de_html("docs/i.html", html(cabeca=dup)))
    assert any("Content-Security-Policy" in e
               for e in V.problemas_de_html("docs/i.html", fora + "<body>" + meta + "</body></html>"))


def test_pagina_sem_referrer_e_barrada():
    cabeca = CABECA.replace("no-referrer", "origin")
    assert any("referrer" in e for e in V.problemas_de_html("docs/i.html", html(cabeca=cabeca)))


# --- identidade e mensagem de commit -------------------------------------------------------

def test_identidade_confere_nome_e_email_de_autor_e_committer():
    ok = f"{V.LOGIN} <{NOREPLY}> 1790000000 -0300"
    assert V.problemas_de_identidade(ok, ok) == []
    pessoal = "Fulano <fulano" + ARROBA + "gmail.com> 1790000000 -0300"
    assert V.problemas_de_identidade(pessoal, ok)
    assert V.problemas_de_identidade(ok, pessoal)
    assert V.problemas_de_identidade(f"Fulano <{NOREPLY}> 1 +0000", ok)


def test_mensagem_de_commit_com_vazamento_e_barrada():
    msg = "corrige pagina\n\nenviado de fulano" + ARROBA + "gmail.com\n# comentario ignorado\n"
    assert any("e-mail" in e for e in V.problemas_de_mensagem(msg))
    rodape = "ok\n\nCo-Authored-By: Claude <noreply" + ARROBA + "anthropic.com>\n"
    assert V.problemas_de_mensagem(rodape) == []


# --- pre-push: todos os commits que vao sair, nao so o ultimo ------------------------------

def _git(repo, *args, env_extra=None):
    import os
    env = dict(os.environ, **(env_extra or {}))
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=True, env=env).stdout


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.name", V.LOGIN)
    _git(tmp_path, "config", "user.email", NOREPLY)
    _git(tmp_path, "config", "core.hooksPath", "/dev/null")
    (tmp_path / "README.md").write_text("ok\n", encoding="utf-8")
    _git(tmp_path, "add", "README.md")
    _git(tmp_path, "commit", "-q", "-m", "inicial")
    return tmp_path


def test_pre_push_aprova_commits_limpos(repo):
    shas = _git(repo, "rev-list", "HEAD").split()
    assert V.problemas_dos_commits(shas, raiz=repo) == []


def test_pre_push_pega_autor_pessoal_mensagem_e_conteudo(repo):
    pessoal = "fulano" + ARROBA + "gmail.com"
    (repo / "README.md").write_text("contato " + pessoal + "\n", encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "manda para " + pessoal,
         env_extra={"GIT_AUTHOR_NAME": "Fulano", "GIT_AUTHOR_EMAIL": pessoal})
    erros = V.problemas_dos_commits(_git(repo, "rev-list", "HEAD").split(), raiz=repo)
    texto = "\n".join(erros)
    assert "identidade" in texto and "mensagem" in texto and "README.md" in texto


# --- o repositorio real -------------------------------------------------------------------

def test_repositorio_real_passa_na_trava():
    assert V.verificar() == []


def test_paginas_reais_passam_no_parser():
    for pagina in ("docs/index.html", "docs/privacidade.html"):
        texto = (V.RAIZ / pagina).read_text(encoding="utf-8")
        assert V.problemas_de_html(pagina, texto) == [], pagina
