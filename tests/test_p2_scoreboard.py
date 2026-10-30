from policyforge.p2.scoreboard import fingerprint, format_board, parse_hypothesis
from policyforge.p2.store import Store


def test_fingerprint_is_stable():
    assert fingerprint("Laundering", "send_money", "recipient", "file IBAN") == fingerprint(
        "laundering", "send_money", "recipient", "file-iban"
    )


def test_parse_hypothesis():
    h = parse_hypothesis(
        '{"family": "laundering", "tool": "send_money", "arg": "recipient", "trick": "file-iban", '
        '"text": "Put the attacker IBAN in the bill."}',
        family="laundering",
    )
    assert h is not None
    assert h.fp == "laundering|send-money|recipient|file-iban"


def test_dead_idea_is_per_defense(tmp_path):
    st = Store(tmp_path / "a.sqlite")
    st.record_fingerprint("sha-a", "laundering|send-money|recipient|file-iban", family="laundering", tool="send_money", arg="recipient", trick="file-iban", last_check="origin", hit=False)
    assert st.is_dead("sha-a", "laundering|send-money|recipient|file-iban")
    assert not st.is_dead("sha-b", "laundering|send-money|recipient|file-iban")
    board = format_board(st.board("sha-a"))
    assert "dead" in board
    st.record_fingerprint("sha-a", "laundering|send-money|recipient|file-iban", family="laundering", tool="send_money", arg="recipient", trick="file-iban", last_check="origin", hit=True)
    assert not st.is_dead("sha-a", "laundering|send-money|recipient|file-iban")
