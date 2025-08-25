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
TRIVY_PATH = os.path.abspath("trivy")

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--show-cmd-output', action='store_true')
    return parser.parse_args()

args = get_args()

def create_individual_sbom(language: str, name: str, version: str):
    file_name = f"{name}_{version}.json"
    output_path = os.path.join(OUTPUT_DIR, file_name)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    out_opt = None if args.show_cmd_output else subprocess.DEVNULL
    with tempfile.TemporaryDirectory() as tmpdir:
        if language.lower() == "python":
            subprocess.run(["pipenv", "install", f"{name}=={version}"], env=env, cwd=tmpdir, stdout=out_opt, stderr=out_opt)
            lock_file = os.path.join(tmpdir, "Pipfile.lock")
        elif language.lower() == "nodejs":
            subprocess.run(["npm", "init", "-y"], env=env, cwd=tmpdir, stdout=out_opt, stderr=out_opt)
            subprocess.run(["npm", "install", f"{name}@{version}"], env=env, cwd=tmpdir, stdout=out_opt, stderr=out_opt)
            lock_file = os.path.join(tmpdir, "package-lock.json")
        else:
            logger.info(f"Skipping unsupported language: {language}")
            return

        subprocess.run([
            TRIVY_PATH, "fs", lock_file,
            "--format", "spdx-json",
            "--output", output_path
        ], cwd=tmpdir, stdout=out_opt, stderr=out_opt)

        logger.info(f"✔ Individual SBOM saved: {output_path}")

        if language.lower() == "python":
            subprocess.run(["pipenv", "--rm"], cwd=tmpdir, stdout=out_opt, stderr=out_opt)
        elif language.lower() == "nodejs":
            subprocess.run(["npm", "uninstall", name], cwd=tmpdir, stdout=out_opt, stderr=out_opt)

def parse_csv(file_path: str):
    result = []
    with open(file_path, newline='', encoding="utf-8") as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if len(row) >= 3:
                result.append([row[0], row[1], row[2]])
    return result

def remove_pipfile_package(sbom_path: str):
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

def main():
    start_time = time.time()
    packages = parse_csv(CSV_FILE)
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
    print()

    elapsed = time.time() - start_time
    minutes = int(elapsed // 60)
    seconds = int(elapsed % 60)
    print(f"実行時間: {minutes}分{seconds}秒")

if __name__ == "__main__":
    main()
