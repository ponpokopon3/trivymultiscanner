import os
import csv
import tempfile
import subprocess
import logging
import json
import sys
import time
import argparse
import shutil

OUTPUT_DIR = os.path.abspath("output")
LOG_FILE = os.path.join(OUTPUT_DIR, "app.log")

os.makedirs(OUTPUT_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8")]
)
logger = logging.getLogger(__name__)

CSV_FILE = os.path.abspath("input.csv")
TRIVY_PATH = os.environ.get("TRIVY_PATH") or shutil.which("trivy") or os.path.abspath("trivy.exe")

def get_args():
    p = argparse.ArgumentParser()
    p.add_argument('--debug', action='store_true', help='DEBUGログを有効にする')
    return p.parse_args()

args = get_args()

def _run(cmd, *, cwd=None, env=None):
    out = None if args.debug else subprocess.DEVNULL
    err = None if args.debug else subprocess.DEVNULL
    subprocess.run(cmd, check=True, cwd=cwd, env=env, stdout=out, stderr=err)

def create_individual_sbom(language: str, name: str, version: str) -> None:
    file_name = f"{name}_{version}.json"
    output_path = os.path.join(OUTPUT_DIR, file_name)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # ---- 共通環境 ----
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    # pipenv を確実に隔離・作成
    env["PIPENV_VENV_IN_PROJECT"] = "1"
    env["PIPENV_IGNORE_VIRTUALENVS"] = "1"

    out_opt = None if args.debug else subprocess.DEVNULL

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            lang = language.lower().strip()
            if lang == "python":
                # Pipfile/Pipfile.lock を tmpdir に作成
                # 1) 明示的に現在の Python を指定して pipenv を起動
                pipenv_base = [sys.executable, "-m", "pipenv"]
                _run(pipenv_base + ["--python", sys.executable], cwd=tmpdir, env=env)

                # 2) 目的パッケージを追加（インストール）
                _run(pipenv_base + ["install", f"{name}=={version}"], cwd=tmpdir, env=env)

                # 3) 念のため lock 生成（install で出来ているはずだが明示）
                _run(pipenv_base + ["lock"], cwd=tmpdir, env=env)

                lock_file = os.path.join(tmpdir, "Pipfile.lock")

            elif lang == "nodejs":
                # Node は従来どおり
                _run(["npm", "init", "-y"], cwd=tmpdir, env=env)
                _run(["npm", "install", f"{name}@{version}"], cwd=tmpdir, env=env)
                lock_file = os.path.join(tmpdir, "package-lock.json")
            else:
                logger.info(f"Skipping unsupported language: {language}")
                return

            # ---- Trivy 実行（あなたの元のやり方を踏襲）----
            trivy_cmd = [
                TRIVY_PATH, "fs", lock_file,
                "--format", "spdx-json",
                "--output", output_path,
            ]
            _run(trivy_cmd, cwd=tmpdir, env=env)
            logger.info(f"✔ Individual SBOM saved: {output_path}")

        except subprocess.CalledProcessError as e:
            logger.error(f"✖ Failed to generate SBOM for {name}=={version}: {e}")
        finally:
            # ---- 後片付け：pipenv も python -m で確実に ----
            try:
                if lang == "python":
                    pipenv_base = [sys.executable, "-m", "pipenv"]
                    _run(pipenv_base + ["--rm"], cwd=tmpdir, env=env)
                elif lang == "nodejs":
                    _run(["npm", "uninstall", name], cwd=tmpdir, env=env)
            except Exception:
                pass

def parse_csv(file_path: str) -> list[list[str]]:
    result: list[list[str]] = []
    try:
        with open(file_path, newline='', encoding="utf-8") as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if len(row) < 3:
                    continue
                result.append([row[0], row[1], row[2]])
    except Exception as e:
        logger.error(f"Failed to read CSV file: {file_path} ({e})")
    return result

def remove_pipfile_package(sbom_path: str) -> None:
    if not os.path.exists(sbom_path):
        logger.error(f"SBOM file not found: {sbom_path}")
        return
    with open(sbom_path, encoding="utf-8") as f:
        data = json.load(f)

    pipfile_spdxids = [
        pkg.get("SPDXID")
        for pkg in data.get("packages", [])
        if (pkg.get("name") or "").find("Pipfile.lock") >= 0
    ]

    data["packages"] = [
        pkg for pkg in data.get("packages", [])
        if (pkg.get("name") or "").find("Pipfile.lock") < 0
    ]

    if "relationships" in data and pipfile_spdxids:
        data["relationships"] = [
            rel for rel in data["relationships"]
            if rel.get("spdxElementId") not in pipfile_spdxids
            and rel.get("relatedSpdxElement") not in pipfile_spdxids
        ]

    with open(sbom_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def main() -> None:
    start_time = time.time()
    packages: list[list[str]] = parse_csv(CSV_FILE)
    if not packages:
        logger.warning("No packages found in CSV file.")
        return

    total = len(packages)
    for i, (language, name, version) in enumerate(packages, 1):
        create_individual_sbom(language, name, version)
        remove_pipfile_package(os.path.join(OUTPUT_DIR, f"{name}_{version}.json"))
        percent = int(i / total * 100)
        sys.stdout.write(f"\rパッケージ処理中: {i}/{total} ({percent}%)")
        sys.stdout.flush()
    print()

    elapsed = time.time() - start_time
    print(f"実行時間: {int(elapsed//60)}分{int(elapsed%60)}秒")

if __name__ == "__main__":
    main()
