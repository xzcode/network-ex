"""Collect only expected native installer outputs; preserve app bundle modes in DMG."""
import hashlib
import pathlib
import shutil
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
target, label = sys.argv[1:]
expected = {
    "aarch64-apple-darwin": ("macos-arm64", "dmg", "*.dmg", "macos"),
    "x86_64-apple-darwin": ("macos-x64", "dmg", "*.dmg", "macos"),
    "x86_64-pc-windows-msvc": ("windows-x64", "nsis", "*.exe", "windows"),
    "x86_64-unknown-linux-gnu": ("linux-x64", "deb", "*.deb", "linux"),
}
if target not in expected or expected[target][0] != label:
    raise SystemExit("Unexpected target")
_, sub, pattern, platform = expected[target]
bundle = ROOT / "apps/desktop/src-tauri/target" / target / "release/bundle" / sub
files = sorted(bundle.glob(pattern))
if not files:
    raise SystemExit(f"No expected installers under {bundle}")
out = ROOT / "artifacts" / ("desktop-" + label)
out.mkdir(parents=True, exist_ok=False)
for f in files:
    shutil.copy2(f, out / f.name)
sidecar = ROOT / "apps/desktop/src-tauri/binaries" / ("network-ex-agent-" + target + (".exe" if platform == "windows" else ""))
shutil.copy2(sidecar, out / ("network-ex-agent.exe" if platform == "windows" else "network-ex-agent"))
shutil.copytree(ROOT / "deploy" / platform, out / "agent-service")
(out / "README.txt").write_text(
    "Network EX development artifacts. Native installation and network runtime are not certified.\n"
    "The desktop program is not the privileged Agent service. Install the matching Agent\n"
    "using the candidate scripts in agent-service only after reviewing their requirements.\n"
    "Windows requires an official matching signed Wintun DLL; current pipe requires elevated admin.\n"
    "macOS is ad-hoc signed, not Developer ID notarized. Do not disable system security.\n"
    "No Apple distribution signature or Windows Authenticode is supplied.\n",
    encoding="utf-8",
)
hashes = []
for f in sorted(out.rglob("*")):
    if f.is_file():
        with f.open("rb") as h:
            digest = hashlib.file_digest(h, "sha256").hexdigest()
        hashes.append(digest + "  " + f.relative_to(out).as_posix())
(out / "SHA256SUMS").write_text("\n".join(hashes) + "\n", encoding="utf-8")
print("Collected", len(hashes), "files for", label)
