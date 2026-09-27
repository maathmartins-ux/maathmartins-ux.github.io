"""A trava pega o que vazaria num repositorio publico e aprova o site real.

Os exemplos ruins sao montados em tempo de execucao (concatenacao) para que este
arquivo, que tambem e publico, nao contenha nenhum dado com cara de verdadeiro.
"""
import pytest

import verificar_site as V

ARROBA = "@"
PAGINA_OK = (
    '<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">'
    "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'self'\">"
    '<meta name="referrer" content="no-referrer"><title>T</title></head>'
    '<body><a href="https://exemplo.org/">x</a></body></html>'
)


@pytest.mark.parametrize("vazamento, tipo", [
    ("contato: fulano" + ARROBA + "exemplo.com", "e-mail"),
    ("AIza" + "B" * 35, "chave de API do Google"),
    ("GOCSPX-" + "a1b2c3d4e5f6", "segredo de cliente OAuth do Google"),
    ("ghp_" + "x" * 36, "token do GitHub"),
    ("sk-ant-" + "y" * 30, "chave de API (sk-)"),
    ("123456789:" + "A" * 35, "token de bot do Telegram"),
    ("-----BEGIN " + "RSA PRIVATE KEY-----", "chave privada"),
    ('"client_' + 'secret": "abc"', "campo de credencial"),
    ("123.456.789-" + "09", "CPF"),
    ("C:" + "\\Users\\alguem\\arquivo", "caminho do computador"),
    ("(11) 9" + "8765-4321", "telefone"),
])
def test_vazamento_e_barrado(vazamento, tipo):
    erros = V.problemas_de_conteudo("docs/x.html", f"<p>{vazamento}</p>".encode())
    assert any(tipo in e for e in erros), erros


def test_handle_do_canal_e_links_publicos_nao_sao_email():
    texto = ('<a href="https://www.youtube.com/' + ARROBA + 'choquesinaptico2760">canal</a>'
             '<a href="https://myaccount.google.com/permissions">x</a>')
    assert V.problemas_de_conteudo("docs/index.html", texto.encode()) == []


def test_binario_e_barrado():
    assert V.problemas_de_conteudo("docs/logo.png", b"\x89PNG\x00\x00")


@pytest.mark.parametrize("caminho", [
    ".env", "config/.env.local", "dados.json", "chave.pem", "client_secret_123.json",
    "youtube_token.txt", "banco.sqlite3", "saida.log",
])
def test_arquivo_proibido_e_barrado(caminho):
    assert V.problemas_de_nome(caminho)


@pytest.mark.parametrize("caminho", ["docs/app.js", "docs/foto.png"])
def test_site_so_publica_html_e_css(caminho):
    assert any("so publica" in e for e in V.problemas_de_nome(caminho))


@pytest.mark.parametrize("caminho", ["docs/index.html", "docs/estilo.css", "docs/.nojekyll", "README.md"])
def test_arquivo_legitimo_passa(caminho):
    assert V.problemas_de_nome(caminho) == []


def test_pagina_protegida_passa():
    assert V.problemas_de_html("docs/index.html", PAGINA_OK) == []


@pytest.mark.parametrize("trecho, motivo", [
    ("<script>alert(1)</script>", "script"),
    ('<form action="https://x.org">', "formulario"),
    ('<iframe src="https://x.org">', "iframe"),
    ('<img src="a.png" onerror="x()">', "evento inline"),
    ('<a href="javascript:x()">', "javascript:"),
    ('<a href="http://x.org">', "sem https"),
])
def test_superficie_de_ataque_e_barrada(trecho, motivo):
    pagina = PAGINA_OK.replace("</body>", trecho + "</body>")
    assert any(motivo in e for e in V.problemas_de_html("docs/index.html", pagina))


def test_pagina_sem_csp_ou_referrer_e_barrada():
    sem = PAGINA_OK.replace("default-src 'none'", "default-src *").replace("no-referrer", "origin")
    erros = V.problemas_de_html("docs/index.html", sem)
    assert any("Content-Security-Policy" in e for e in erros)
    assert any("referrer" in e for e in erros)


def test_identidade_pessoal_e_barrada_e_noreply_passa():
    assert V.problema_de_identidade("fulano" + ARROBA + "gmail.com")
    assert V.problema_de_identidade("")
    assert V.problema_de_identidade("123+login" + ARROBA + "users.noreply.github.com") == []


def test_repositorio_real_passa_na_trava():
    assert V.verificar() == []
