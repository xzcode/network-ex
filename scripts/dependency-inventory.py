"""Generate binary-derived Go SBOM and capture module license notices.

This covers linked Go modules, not the complete operating-system, C or
desktop/mobile dependency graph. Missing license texts are a release gate.
"""
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys

out, version = pathlib.Path(sys.argv[1]), sys.argv[2]
def run(*args):
    return subprocess.check_output(args, text=True)
def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for data in iter(lambda: f.read(1 << 20), b""):
            digest.update(data)
    return digest.hexdigest()
licenses = out / "third-party-notices"
licenses.mkdir()
components = {}
dependencies = []
for name in ("network-ex-server", "network-ex-agent"):
    binary = out / name
    refs = []
    info = run("go", "version", "-m", str(binary))
    (out / (name + ".buildinfo.txt")).write_text(info, encoding="utf-8")
    for line in info.splitlines():
        row = line.split()
        if not row or row[0] != "dep" or len(row) < 3:
            continue
        path, ver = row[1:3]
        ref = f"go:{path}@{ver}"
        refs.append(ref)
        if ref in components:
            continue
        comp = {"type": "library", "name": path, "version": ver, "bom-ref": ref, "purl": f"pkg:golang/{path}@{ver}"}
        if len(row)>3:
            comp["properties"] = [{"name":"network-ex:go-module-sum","value":row[3]}]
        components[ref] = comp
    ref = "binary:" + name
    components[ref] = {"type":"application","name":name,"version":version,"bom-ref":ref,"hashes":[{"alg":"SHA-256","content":sha256(binary)}]}
    dependencies.append({"ref":ref,"dependsOn":sorted(set(refs))})
missing = []
for ref, comp in sorted(components.items()):
    if not ref.startswith("go:"):
        continue
    path, ver = comp["name"], comp["version"]
    module = json.loads(run("go", "mod", "download", "-json", path+"@"+ver))
    directory = pathlib.Path(module["Dir"])
    dest = licenses / (re.sub(r"[^a-zA-Z0-9._-]", "_", path) + "-" + hashlib.sha256(path.encode()).hexdigest()[:8])
    candidates = [p for p in directory.iterdir() if p.is_file() and re.match(r"(?i)^(license|licence|copying|notice|copyright)([._-].*|$)", p.name)]
    if not candidates:
        missing.append(path+"@"+ver)
        continue
    dest.mkdir()
    for p in candidates:
        shutil.copy2(p, dest / p.name)
    comp.setdefault("properties", []).append({"name":"network-ex:license-notice-directory","value":str(dest.relative_to(out))})
bom={"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"metadata":{"component":{"type":"application","name":"Network EX Linux development","version":version},"properties":[{"name":"network-ex:scope","value":"linked Go modules only; C/OS dependencies require separate review"}]},"components":list(components.values()),"dependencies":dependencies}
(out/"sbom-go.cdx.json").write_text(json.dumps(bom,indent=2)+"\n",encoding="utf-8")
(out/"LICENSE_REVIEW.txt").write_text("Project licensing is not selected. Third-party notice capture is not legal approval.\nReview C SQLite source, Go standard library, OS libraries and all other platform dependencies separately.\nModules missing top-level notice files:\n"+("\n".join(missing) or "(none)")+"\n",encoding="utf-8")
print("Binary-derived SBOM:",len(components),"components;",len(missing),"missing notices")
