"""Ground truth from fixture implementations, never scanner assessments."""
from experiments.evaluation.common import ROOT, digest


def catalog():
    sql_source = "experiments/sqlite_control.py"
    xss_source = "experiments/xss_lab.py"
    exposure_source = "experiments/exposure_lab.py"

    def unit(uid, module, truth, parameter=None, file_path=None, stratum="principal", reason="", source=sql_source):
        return dict(unit_id=uid, module=module, truth=truth, parameter=parameter, file_path=file_path,
                    stratum=stratum, oracle=dict(source=source, sha256=digest(ROOT / source), reason=reason,
                    symbol="searchProducts" if source.startswith("lab/") else "response" if source != sql_source else "ProductDatabase.search / ControlHandler.do_GET / general_search"))

    def case(cid, module, path, units, budget, **options):
        return dict(case_id=cid, module=module, path=path, units=units, budget=budget,
                    conditions=["default"], **options)

    cases = []
    definitions = [
        ("/control/vulnerable/search?q=apple", "q", False, "like"),
        ("/control/safe/search?q=apple", "q", True, "like"),
        ("/general/json/vulnerable?term=apple&lang=en", "term", False, "like"),
        ("/general/json/safe?term=apple&lang=en", "term", True, "like"),
        ("/general/html/vulnerable?search=apple&lang=en", "search", False, "like"),
        ("/general/html/safe?search=apple&lang=en", "search", True, "like"),
        ("/general/text/vulnerable?keyword=apple&lang=en", "keyword", False, "like"),
        ("/general/text/safe?keyword=apple&lang=en", "keyword", True, "like"),
        ("/general/quoted/vulnerable?item=Apple+Demo", "item", False, "quoted"),
        ("/general/quoted/safe?item=Apple+Demo", "item", True, "quoted"),
        ("/general/html/vulnerable?search=apple&lang=en", "search", False, "like"),
        ("/general/html/unstable?search=apple", "search", True, "like"),
        ("/general/html/error?search=apple", "search", True, "like"),
        ("/general/json/vulnerable?term=apple", "term", False, "quoted"),
    ]
    for n, (path, param, bound, context) in enumerate(definitions, 1):
        cid = f"S{n:02d}"
        stratum = "diagnostic" if n >= 12 else "principal"
        reason = "ProductDatabase.search uses bound SQL parameters" if bound else "ProductDatabase.search interpolates input into SQL"
        if n == 13:
            reason = "general_search error branch returns fixed HTML before executing a query"
        units = [unit(cid + "a", "sqli", "safe" if bound else "vulnerable", param,
                      stratum=stratum, reason=reason)]
        if n == 11:
            units.append(unit(cid + "b", "sqli", "safe", "lang", reason="lang changes escaped presentation, not the SQL query"))
        cases.append(case(cid, "sqli", path, units, 20 if n == 11 else 10, context=context, all_parameters=n == 11))

    xpaths = ["/xss/html/raw", "/xss/attribute/raw", "/xss/script/raw", "/xss/html/escaped",
              "/xss/attribute/escaped", "/xss/script/escaped", "/xss/json", "/xss/text", "/health", "/xss/csp"]
    for n, path in enumerate(xpaths, 1):
        cid = f"X{n:02d}"
        truth = "vulnerable" if n <= 3 else "mitigated" if n == 10 else "safe"
        reasons = {"vulnerable": "response interpolates input into executable HTML/attribute/JavaScript",
                   "safe": "contextual encoding or non-HTML nosniff response; health ignores q",
                   "mitigated": "unescaped interpolation with script-src none; separate mitigated stratum"}
        c = case(cid, "xss", path + "?q=demo", [unit(cid + "a", "xss", truth, "q",
                 stratum="mitigated" if n == 10 else "principal", reason=reasons[truth],
                 source=sql_source if n == 9 else xss_source)], 10)
        c["conditions"] = ["static", "browser"]
        cases.append(c)

    files = {"config": [".env", "config.ini"], "backup": ["backup.sql", "config.ini.bak"], "repository": [".git/HEAD"]}
    n = 0
    for branch in ["exposed", "root", "blocked", "missing", "fallback", "error"]:
        for profile, paths in files.items():
            n += 1
            cid = f"E{n:02d}"
            units = []
            for i, path in enumerate(paths):
                positive = branch == "exposed" or branch == "root" and path in {".env", "backup.sql"}
                units.append(unit(cid + chr(97+i), "exposure", "vulnerable" if positive else "safe", file_path=path,
                    stratum="diagnostic" if branch == "error" else "principal", source=exposure_source,
                    reason="response fixture maps this file to a designated private fictional artifact" if positive else
                    "response fixture is blocked/missing/public documentation/HTML fallback or HTML error"))
            cases.append(case(cid, "exposure", "/" if branch == "root" else f"/exposure-lab/{branch}/",
                              units, len(paths)*4, profile=profile))
    # Integrated workflows are descriptive, not duplicates in direct-detector matrices.
    cases.append(case("I01", "scan", "/probekit-lab", [], 100, domain="integration"))
    cases.append(case("J01", "scan", "/", [], 100, domain="juice"))
    cases.append(case("J02", "sqli", "/rest/products/search?q=apple", [unit("J02a", "sqli", "vulnerable", "q",
        stratum="application", source="lab/juice-shop_20.3.0/build/routes/search.js",
        reason="searchProducts interpolates req.query.q into a LIKE query; source independent of scanner")],
        10, domain="juice", context="like", all_parameters=False))
    return dict(catalog_version="1.0.0", repetitions=3, cases=cases)
