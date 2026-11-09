import pytest

from scanner.terminal import safe_text


@pytest.mark.parametrize('value', ['\x1b[2J', '\x1b]0;title\x07', '\x1b[', '\x00\x08\r\n\t\x7f\x85\x9b31m'])
def test_untrusted_controls_are_visible(value):
    text = safe_text(value)
    assert all(ord(char) >= 32 and not 127 <= ord(char) <= 159 for char in text)
    assert '\\x' in text


def test_unicode_is_preserved():
    assert safe_text('ação 中文 😀 e\u0301') == 'ação 中文 😀 e\u0301'


def test_percent_encoded_parameter_keeps_wire_value_and_terminal_inert(http_lab, tmp_path, capsys):
    from main import main
    name = '\x1b[2J'
    site = http_lab.start(lambda _: http_lab.reply())
    assert main([site.url + '?%1b%5b2J=demo', '--module', 'xss', '--interval', '0',
                 '--evidence-profile', 'restricted', '--output', str(tmp_path / 'full.json')]) == 0
    terminal = capsys.readouterr()
    assert '\x1b' not in terminal.out + terminal.err
    assert '\\x1b[2J' in terminal.out
    assert all(name in call.query for call in site.calls)


def test_argparse_sanitizes_restricted_errors(capsys):
    from main import main
    with pytest.raises(SystemExit) as error:
        main(['http://127.0.0.1/', '--bad\x1b]title\x07', '--evidence-profile', 'restricted'])
    assert error.value.code == 2
    text = capsys.readouterr().err
    assert '\x1b' not in text and '\x07' not in text and '\\x1b' in text


def test_last_profile_option_also_controls_argument_failures(capsys):
    from main import main
    with pytest.raises(SystemExit):
        main(['http://127.0.0.1/', '--evidence-profile', 'restricted',
              '--evidence-profile=shareable', '--PRIVATE_SENTINEL'])
    assert 'PRIVATE_SENTINEL' not in capsys.readouterr().err
