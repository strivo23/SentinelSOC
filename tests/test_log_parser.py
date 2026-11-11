from core.log_parser import parse_line,parse_lines

def test_parse_failed_and_accepted():
    failed=parse_line("Feb 14 09:00:00 host sshd[10]: Failed password for admin from 203.0.113.1 port 4444 ssh2",2025)
    success=parse_line("Feb 14 09:01:00 host sshd[10]: Accepted publickey for alice from 192.0.2.2 port 22 ssh2",2025)
    assert (failed["outcome"],failed["username"],failed["source_ip"])==("failed","admin","203.0.113.1")
    assert (success["outcome"],success["username"])==("success","alice")

def test_malformed_invalid_user_and_duplicate():
    line="Feb 14 09:00:00 host sshd[10]: Invalid user guest from 203.0.113.1 port 4"
    assert parse_line("not a log",2025) is None
    assert parse_line("Feb 31 09:00:00 host sshd: nope",2025) is None
    assert parse_line(line,2025)["is_invalid_user"]
    assert len(parse_lines([line,line],2025))==1
