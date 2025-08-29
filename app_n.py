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

# 出力ディレクトリとログファイルのパスを定義
OUTPUT_DIR = os.path.abspath("output")
LOG_FILE = os.path.join(OUTPUT_DIR, "app.log")

# 出力ディレクトリを作成（存在しない場合のみ）
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ログ設定
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8")]
)
logger = logging.getLogger(__name__)

# 入力CSVファイルとTrivyのパスを定義
CSV_FILE = os.path.abspath("input.csv")
TRIVY_PATH = os.environ.get("TRIVY_PATH") or shutil.which("trivy") or os.path.abspath("trivy.exe")

def get_args():
    """
    コマンドライン引数のパーサー
    --debug オプションで詳細ログを有効化
    """
    p = argparse.ArgumentParser()
    p.add_argument('--debug', action='store_true', help='DEBUGログを有効にする')
    return p.parse_args()

args = get_args()

def _run(cmd, *, cwd=None, env=None):
    """
    サブプロセス実行のラッパー関数
    デバッグモード以外は標準出力・エラーを抑制
    """
    out = None if args.debug else subprocess.DEVNULL
    err = None if args.debug else subprocess.DEVNULL
    subprocess.run(cmd, check=True, cwd=cwd, env=env, stdout=out, stderr=err)

def create_nodejs_sbom(name: str, version: str) -> None:
    """
    Node.jsパッケージのSBOM（SPDX形式）を生成
    一時ディレクトリでnpmプロジェクトを初期化し、指定パッケージをインストール
    TrivyでSBOMをpackage-lock.jsonを対象に出力
    """
    file_name = f"nodejs_{name}_{version}.json"
    output_path = os.path.join(OUTPUT_DIR, file_name)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            # npmプロジェクト初期化
            _run(["npm", "init", "-y"], cwd=tmpdir)
            # パッケージインストール
            _run(["npm", "install", f"{name}@{version}"], cwd=tmpdir)
            lock_file = os.path.join(tmpdir, "package-lock.json")
            # TrivyでSBOM出力（package-lock.jsonを対象）
            trivy_cmd = [
                TRIVY_PATH, "fs", lock_file,
                "--format", "spdx-json",
                "--output", output_path,
            ]
            _run(trivy_cmd, cwd=tmpdir)
            logger.info(f"✔ Node.js SBOM saved: {output_path}")
        except subprocess.CalledProcessError as e:
            logger.error(f"✖ Failed to generate Node.js SBOM for {name}@{version}: {e}")

def create_python_sbom(name: str, version: str) -> None:
    """
    PythonパッケージのSBOM（SPDX形式）を生成
    一時ディレクトリでpipenv環境を構築し、指定パッケージをインストール
    TrivyでSBOMを出力
    """
    file_name = f"python_{name}_{version}.json"
    output_path = os.path.join(OUTPUT_DIR, file_name)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PIPENV_VENV_IN_PROJECT"] = "1"
    env["PIPENV_IGNORE_VIRTUALENVS"] = "1"

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            pipenv_base = [sys.executable, "-m", "pipenv"]
            # 仮想環境作成とパッケージインストール
            _run(pipenv_base + ["--python", sys.executable], cwd=tmpdir, env=env)
            _run(pipenv_base + ["install", f"{name}=={version}"], cwd=tmpdir, env=env)
            _run(pipenv_base + ["lock"], cwd=tmpdir, env=env)
            lock_file = os.path.join(tmpdir, "Pipfile.lock")

            # TrivyでSBOM出力
            trivy_cmd = [
                TRIVY_PATH, "fs", lock_file,
                "--format", "spdx-json",
                "--output", output_path,
            ]
            _run(trivy_cmd, cwd=tmpdir, env=env)
            logger.info(f"✔ Python SBOM saved: {output_path}")

        except subprocess.CalledProcessError as e:
            logger.error(f"✖ Failed to generate Python SBOM for {name}=={version}: {e}")
        finally:
            try:
                # 仮想環境のクリーンアップ
                pipenv_base = [sys.executable, "-m", "pipenv"]
                _run(pipenv_base + ["--rm"], cwd=tmpdir, env=env)
            except Exception:
                pass

def create_individual_sbom(language: str, name: str, version: str) -> None:
    """
    言語ごとにSBOM生成関数を呼び分け
    Python・Node.jsのみ対応
    """
    lang = language.lower().strip()
    if lang == "python":
        create_python_sbom(name, version)
    elif lang == "nodejs":
        create_nodejs_sbom(name, version)
    else:
        logger.info(f"Skipping unsupported language: {language}")
        return

def parse_csv(file_path: str) -> list[list[str]]:
    """
    入力CSVファイルをパースし、[言語, パッケージ名, バージョン]のリストを返す
    """
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

def merge_sbom_files(output_dir: str, merged_file: str) -> None:
    """
    SPDX形式のSBOMファイルをマージする。
    'python_'がファイル名に含まれるSBOMのみ対象。
    'Pipfile.lock'関連のパッケージ（nameが'Pipfile.lock'またはパスに含むもの）は除外する。
    最初のSBOMファイルのメタデータ（spdxVersion, dataLicense, name, documentNamespace, creationInfoなど）は残す。
    """
    merged_data = {
        "spdxVersion": None,
        "dataLicense": None,
        "SPDXID": None,
        "name": None,
        "documentNamespace": None,
        "creationInfo": None,
        "packages": [],
        "relationships": []
    }
    pipfile_spdxids = set()
    first_metadata = None

    # python_が付いているファイルのみ対象
    for filename in os.listdir(output_dir):
        if filename.startswith("python_") and filename.endswith(".json"):
            filepath = os.path.join(output_dir, filename)
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)
            # 最初のSBOMファイルのメタデータを保存
            if not first_metadata:
                for key in ["spdxVersion", "dataLicense", "SPDXID", "name", "documentNamespace", "creationInfo"]:
                    if key in data:
                        merged_data[key] = data[key]
                first_metadata = True
            # Pipfile.lock関連のSPDXIDを収集
            for pkg in data.get("packages", []):
                name = pkg.get("name", "")
                if name == "Pipfile.lock" or ("Pipfile.lock" in name):
                    pipfile_spdxids.add(pkg.get("SPDXID"))

    # マージ処理（除外対象を除く）
    for filename in os.listdir(output_dir):
        if filename.startswith("python_") and filename.endswith(".json"):
            filepath = os.path.join(output_dir, filename)
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)
            merged_data["packages"].extend([
                pkg for pkg in data.get("packages", [])
                if pkg.get("SPDXID") not in pipfile_spdxids
            ])
            merged_data["relationships"].extend([
                rel for rel in data.get("relationships", [])
                if rel.get("spdxElementId") not in pipfile_spdxids
                and rel.get("relatedSpdxElement") not in pipfile_spdxids
            ])
    # マージ結果をファイル出力
    with open(merged_file, "w", encoding="utf-8") as f:
        json.dump(merged_data, f, ensure_ascii=False, indent=2)

def main() -> None:
    """
    メイン処理
    1. CSVからパッケージリスト取得
    2. 各パッケージごとにSBOM生成
    3. PythonパッケージSBOMをマージ
    4. 実行時間表示
    """
    start_time = time.time()
    packages: list[list[str]] = parse_csv(CSV_FILE)
    if not packages:
        logger.warning("No packages found in CSV file.")
        return

    total = len(packages)
    # 進捗表示
    sys.stdout.write(f"\rパッケージ処理中: 0/{total} (0%)")
    sys.stdout.flush()
    for i, (language, name, version) in enumerate(packages, 1):
        create_individual_sbom(language, name, version)
        percent = int(i / total * 100)
        sys.stdout.write(f"\rパッケージ処理中: {i}/{total} ({percent}%)")
        sys.stdout.flush()
    print()

    # PythonパッケージSBOMをマージ
    merge_sbom_files(OUTPUT_DIR, os.path.join(OUTPUT_DIR, "python_packages.json"))

    elapsed = time.time() - start_time
    print(f"実行時間: {int(elapsed//60)}分{int(elapsed%60)}秒")

if __name__ == "__main__":
    main()
