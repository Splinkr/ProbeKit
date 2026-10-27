"""Confirmação opcional com navegador novo, replay e interceptação de toda a rede."""

import base64
import json
import os
from pathlib import Path
import shutil
import subprocess

from scanner.targets import validate_target

BRIDGE = Path(__file__).resolve().parents[1] / "scripts" / "confirm-xss.mjs"


def invoke_bridge(node, settings, limit):
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    process = subprocess.Popen([node, str(BRIDGE)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, encoding="utf-8", creationflags=flags)

    def stop():
        if process.poll() is None:
            if os.name == "nt":
                # Somente a árvore do helper que acabamos de criar, nunca navegadores do usuário.
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True,
                               creationflags=flags, timeout=5)
            else:
                process.kill()
            process.wait(timeout=5)

    try:
        output, _ = process.communicate(json.dumps(settings), timeout=limit)
    except KeyboardInterrupt:
        try:
            process.communicate(timeout=limit)  # Dá ao helper tempo limitado para fechar o perfil.
        except subprocess.TimeoutExpired:
            stop()
        raise
    except subprocess.TimeoutExpired:
        stop()
        raise
    return subprocess.CompletedProcess([node, str(BRIDGE)], process.returncode, output)


def browser_path():
    candidates = [shutil.which("msedge"), shutil.which("google-chrome"), shutil.which("chromium")]
    for root in (os.environ.get("PROGRAMFILES(X86)"), os.environ.get("PROGRAMFILES")):
        if root:
            candidates.extend([str(Path(root) / "Microsoft/Edge/Application/msedge.exe"),
                               str(Path(root) / "Google/Chrome/Application/chrome.exe")])
    return next((path for path in candidates if path and Path(path).is_file()), None)


def confirm_responses(report, parameter, callback, *, timeout=5.0):
    executable, node = browser_path(), shutil.which("node")
    if not executable or not node:
        return {"status": "unavailable", "confirmed": False, "reason": "Requer Edge/Chrome local e Node com WebSocket nativo; nenhum download é realizado."}
    probes = {probe.role: probe for probe in report.probes if probe.parameter == parameter}
    responses = {response.request_id: response for response in report.responses}
    control = probes["marker_1"]
    candidates = [probe for role, probe in probes.items() if role.startswith("attack_") and probe.content_format == "text/html"]
    cases = []
    for probe in [control, *candidates]:
        response = responses[probe.request_id]
        validate_target(response.url)
        cases.append({"role": probe.role, "request_id": probe.request_id, "marker": probe.marker,
                      "url": response.url, "status": response.status_code, "content_type": response.content_type,
                      "headers": response.security_headers, "body": base64.b64encode(response.body).decode(),
                      "body_sha256": response.body_sha256})
    settings = {"browser": executable, "callback": callback, "cases": cases,
                "timeout_ms": int(min(max(timeout, 2), 10) * 1000)}
    try:
        result = invoke_bridge(node, settings, min(max(timeout, 2), 10) + 15)
        evidence = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        return {"status": "error", "confirmed": False, "reason": "Falha ou timeout na confirmação isolada; não é evidência de execução."}
    # A decisão exige controle negativo, callback do marcador e replay sem tráfego ao alvo.
    runs = evidence.get("cases", [])
    expected = {item["role"]: item for item in cases}
    matched = bool(runs) and len(runs) == len(cases) and all(
        run.get("role") in expected and run.get("marker") == expected[run["role"]]["marker"]
        and run.get("request_id") == expected[run["role"]]["request_id"]
        and run.get("body_sha256") == expected[run["role"]]["body_sha256"]
        and run.get("csp_preserved") for run in runs
    )
    control_ok = bool(runs and runs[0].get("role") == "marker_1" and runs[0].get("replayed") and not runs[0].get("executed"))
    executed = any(run.get("executed") and run.get("main_frame") and run.get("replayed")
                   and run.get("role", "").startswith("attack_") for run in runs)
    evidence["confirmed"] = bool(result.returncode == 0 and evidence.get("status") == "completed"
                                  and evidence.get("target_network_requests") == 0 and matched and control_ok and executed)
    evidence["mode"] = "isolated_browser_response_replay"
    return evidence
