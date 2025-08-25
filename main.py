from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import csv
import tempfile
import subprocess
import logging
import json
import sys
import time
import argparse

LOG_FILE = "trivymultiscanner.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8")
    ]
)
logger = logging.getLogger(__name__)

CSV_FILE = os.path.abspath("input.csv")
OUTPUT_DIR = os.path.abspath("sbom_outputs")
TRIVY_PATH = os.path.abspath("trivy")  # Linuxではtrivyのパスを適宜設定

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true', help='DEBUGログを有効にする')
    parser.add_argument('--show-cmd-output', action='store_true', help='コマンド出力を表示する')
    return parser.parse_args()

args = get_args()

def create_individual_sbom(language: str, name: str, version: str) -> None:
    file_name = f"{name}_{version}.json"
    output_path = os.path.join(OUTPUT_DIR, file_name)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    out_opt = None if args.show_cmd_output else subprocess.DEVNULL
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            if language.lower() == "python":
                pipenv_cmd = [
                    "pipenv", "install", f"{name}=={version}"
                ]
                subprocess.run(
                    pipenv_cmd,
                    check=True,
                    env=env,
                    cwd=tmpdir,
                    stdout=out_opt,
                    stderr=out_opt
                )
                lock_file = os.path.join(tmpdir, "Pipfile.lock")
            elif language.lower() == "nodejs":
                npm_init_cmd = [
                    "npm", "init", "-y"
                ]
                subprocess.run(
                    npm_init_cmd,
                    check=True,
                    env=env,
                    cwd=tmpdir,
                    stdout=out_opt,
                    stderr=out_opt
                )
                npm_install_cmd = [
                    "npm", "install", f"{name}@{version}"
                ]
                subprocess.run(
                    npm_install_cmd,
                    check=True,
                    env=env,
                    cwd=tmpdir,
                    stdout=out_opt,
                    stderr=out_opt
                )
                lock_file = os.path.join(tmpdir, "package-lock.json")
            else:
                logger.info(f"Skipping unsupported language: {language}")
                return

            trivy_cmd = [
                TRIVY_PATH,
                "fs", lock_file,
                "--format", "spdx-json",
                "--output", output_path,
            ]
            subprocess.run(
                trivy_cmd,
                check=True,
                cwd=tmpdir,
                stdout=out_opt,
                stderr=out_opt
            )
            logger.info(f"✔ Individual SBOM saved: {output_path}")
        except subprocess.CalledProcessError as e:
            logger.error(f"✖ Failed to generate SBOM for {name}=={version}: {e}")
        finally:
            try:
                if language.lower() == "python":
                    subprocess.run(
                        ["pipenv", "--rm"],
                        check=True,
                        cwd=tmpdir,
                        stdout=out_opt,
                        stderr=out_opt
                    )
                elif language.lower() == "nodejs":
                    subprocess.run(
                        ["npm", "uninstall", name],
                        check=True,
                        cwd=tmpdir,
                        stdout=out_opt,
                        stderr=out_opt
                    )
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
        pkg["SPDXID"]
        for pkg in data.get("packages", [])
        if pkg.get("name") and "Pipfile.lock" in pkg.get("name")
    ]

    data["packages"] = [
        pkg for pkg in data.get("packages", [])
        if not (pkg.get("name") and "Pipfile.lock" in pkg.get("name"))
    ]

    if "relationships" in data:
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
    with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as executor:
        futures = []
        for package in packages:
            language, name, version = package
            futures.append(executor.submit(
                lambda l, n, v: (
                    create_individual_sbom(l, n, v),
                    remove_pipfile_package(os.path.join(OUTPUT_DIR, f"{n}_{v}.json"))
                ),
                language, name, version
            ))
        for i, future in enumerate(as_completed(futures), 1):
            percent = int(i / total * 100)
            sys.stdout.write(f"\rパッケージ処理中: {i}/{total} ({percent}%)")
    print()  # 改行

    end_time = time.time()
    elapsed = end_time - start_time
    minutes = int(elapsed // 60)
    seconds = int(elapsed % 60)
    print(f"実行時間: {minutes}分{seconds}秒")

if __name__ == "__main__":
    main()
