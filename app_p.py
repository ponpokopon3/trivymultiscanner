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
import re

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

def create_nodejs_sbom(idx: str, name: str, version: str) -> None:
    safe_name = name.replace("/", "_")
    file_name = f"定期調査__Nodejs__{idx.zfill(5)}_nodejs_{safe_name}@{version}.json"
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

            # 'package-lock.json'関連のパッケージを除外
            with open(output_path, encoding="utf-8") as f:
                sbom = json.load(f)
            filtered_packages = [
                pkg for pkg in sbom.get("packages", [])
                if not (pkg.get("name") == "package-lock.json" or "package-lock.json" in str(pkg.get("name")))
            ]
            sbom["packages"] = filtered_packages
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(sbom, f, ensure_ascii=False, indent=2)

        except subprocess.CalledProcessError as e:
            logger.error(f"✖ Failed to generate Node.js SBOM for {name}@{version}: {e}")

def create_python_sbom(idx: str, name: str, version: str) -> None:
    safe_name = name.replace("/", "_")
    file_name = f"定期調査__Python__{idx.zfill(5)}_python_{safe_name}@{version}.json"
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

            # 'Pipfile.lock'関連のパッケージを除外
            with open(output_path, encoding="utf-8") as f:
                sbom = json.load(f)
            filtered_packages = [
                pkg for pkg in sbom.get("packages", [])
                if not (pkg.get("name") == "Pipfile.lock" or "Pipfile.lock" in str(pkg.get("name")))
            ]
            sbom["packages"] = filtered_packages
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(sbom, f, ensure_ascii=False, indent=2)

            # pipenv graph --json の依存関係をSBOMにマッピング
            pipenv_graph_path = os.path.join(tmpdir, "pipenv_graph.json")
            _run(pipenv_base + ["graph", "--json"], cwd=tmpdir, env=env)
            # pipenv graph --json の結果をファイルに保存
            with open(pipenv_graph_path, "w", encoding="utf-8") as f:
                subprocess.run(
                    pipenv_base + ["graph", "--json"],
                    cwd=tmpdir,
                    env=env,
                    stdout=f,
                    stderr=subprocess.DEVNULL,
                    check=True
                )
            # 依存関係をSBOMに反映
            map_pipenv_graph_to_sbom(output_path, pipenv_graph_path)

        except subprocess.CalledProcessError as e:
            logger.error(f"✖ Failed to generate Python SBOM for {name}=={version}: {e}")
        finally:
            try:
                # 仮想環境のクリーンアップ
                pipenv_base = [sys.executable, "-m", "pipenv"]
                _run(pipenv_base + ["--rm"], cwd=tmpdir, env=env)
            except Exception:
                pass

def create_java_sbom(idx: str, name: str, version: str, url: str) -> None:
    safe_name = name.replace("/", "_")
    file_name = f"定期調査__Java__{idx.zfill(5)}_java_{safe_name}@{version}.json"
    output_path = os.path.join(OUTPUT_DIR, file_name)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            # jarファイル名を決定
            jar_file = os.path.join(tmpdir, f"{name}-{version}.jar")
            # ダウンロード（curl/wgetどちらでも可）
            _run(["curl", "-L", "-o", jar_file, url])
            # TrivyでSBOM出力（rootfsスキャン）
            trivy_cmd = [
                TRIVY_PATH, "rootfs", tmpdir,
                "--format", "spdx-json",
                "--output", output_path,
            ]
            _run(trivy_cmd, cwd=tmpdir)
            logger.info(f"✔ Java SBOM saved: {output_path}")
        except subprocess.CalledProcessError as e:
            logger.error(f"✖ Failed to generate Java SBOM for {name}@{version}: {e}")

def create_individual_sbom(idx: str, language: str, name: str, version: str, url: str = None) -> None:
    """
    言語ごとにSBOM生成関数を呼び分け
    """
    lang = language.lower().strip()
    if lang == "python":
        create_python_sbom(idx, name, version)
    elif lang == "nodejs":
        create_nodejs_sbom(idx, name, version)
    elif lang == "java" and url:
        create_java_sbom(idx, name, version, url)
    else:
        logger.info(f"Skipping unsupported language: {language}")
        return

def parse_csv(file_path: str) -> list[list[str]]:
    """
    入力CSVファイルをパースし、[idx, 言語, パッケージ名, バージョン, URL]のリストを返す
    """
    result: list[list[str]] = []
    try:
        with open(file_path, newline='', encoding="utf-8") as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                # javaのみ5列、他は4列
                if len(row) >= 5 and row[1].lower().strip() == "java":
                    result.append([row[0], row[1], row[2], row[3], row[4]])
                elif len(row) >= 4:
                    result.append([row[0], row[1], row[2], row[3], None])
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
        if ("_python_") in filename and filename.endswith(".json"):
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
        if ("_python_") in filename and filename.endswith(".json"):
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

def merge_nodejs_sbom_files(output_dir: str, merged_file: str) -> None:
    """
    SPDX形式のNode.js SBOMファイルをマージする。
    'nodejs_'がファイル名に含まれるSBOMのみ対象。
    'package-lock.json'関連のパッケージ（nameが'package-lock.json'またはパスに含むもの）は除外する。
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
    lock_spdxids = set()
    first_metadata = None

    # nodejs_が付いているファイルのみ対象
    for filename in os.listdir(output_dir):
        if ("_nodejs_") in filename and filename.endswith(".json"):
            filepath = os.path.join(output_dir, filename)
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)
            # 最初のSBOMファイルのメタデータを保存
            if not first_metadata:
                for key in ["spdxVersion", "dataLicense", "SPDXID", "name", "documentNamespace", "creationInfo"]:
                    if key in data:
                        merged_data[key] = data[key]
                first_metadata = True
            # package-lock.json関連のSPDXIDを収集
            for pkg in data.get("packages", []):
                name = pkg.get("name", "")
                if name == "package-lock.json" or ("package-lock.json" in name):
                    lock_spdxids.add(pkg.get("SPDXID"))

    # マージ処理（除外対象を除く）
    for filename in os.listdir(output_dir):
        if ("_nodejs_") in filename and filename.endswith(".json"):
            filepath = os.path.join(output_dir, filename)
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)
            merged_data["packages"].extend([
                pkg for pkg in data.get("packages", [])
                if pkg.get("SPDXID") not in lock_spdxids
            ])
            merged_data["relationships"].extend([
                rel for rel in data.get("relationships", [])
                if rel.get("spdxElementId") not in lock_spdxids
                and rel.get("relatedSpdxElement") not in lock_spdxids
            ])
    # マージ結果をファイル出力
    with open(merged_file, "w", encoding="utf-8") as f:
        json.dump(merged_data, f, ensure_ascii=False, indent=2)

def merge_java_sbom_files(output_dir: str, merged_file: str) -> None:
    """
    SPDX形式のJava SBOMファイルをマージする。
    'java_'がファイル名に含まれるSBOMのみ対象。
    'jar'や一時ディレクトリ関連のパッケージ（nameが一時ディレクトリ名やjarファイル名を含むもの）は除外する。
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
    exclude_spdxids = set()
    first_metadata = None

    # java_が付いているファイルのみ対象
    for filename in os.listdir(output_dir):
        if ("_java_") in filename and filename.endswith(".json"):
            filepath = os.path.join(output_dir, filename)
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)
            # 最初のSBOMファイルのメタデータを保存
            if not first_metadata:
                for key in ["spdxVersion", "dataLicense", "SPDXID", "name", "documentNamespace", "creationInfo"]:
                    if key in data:
                        merged_data[key] = data[key]
                first_metadata = True
            # 一時ディレクトリ名やjarファイル名を含むパッケージのSPDXIDを収集
            for pkg in data.get("packages", []):
                name = pkg.get("name", "")
                if name.endswith(".jar") or "Temp" in name or "tmp" in name:
                    exclude_spdxids.add(pkg.get("SPDXID"))

    # マージ処理（除外対象を除く）
    for filename in os.listdir(output_dir):
        if ("_java_") in filename and filename.endswith(".json"):
            filepath = os.path.join(output_dir, filename)
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)
            merged_data["packages"].extend([
                pkg for pkg in data.get("packages", [])
                if pkg.get("SPDXID") not in exclude_spdxids
            ])
            merged_data["relationships"].extend([
                rel for rel in data.get("relationships", [])
                if rel.get("spdxElementId") not in exclude_spdxids
                and rel.get("relatedSpdxElement") not in exclude_spdxids
            ])
    # マージ結果をファイル出力
    with open(merged_file, "w", encoding="utf-8") as f:
        json.dump(merged_data, f, ensure_ascii=False, indent=2)

def map_pipenv_graph_to_sbom(sbom_file: str, pipenv_graph_file: str) -> None:
    """
    pipenv graph --json の依存関係情報をSBOMのrelationshipsにマッピングする
    """
    # SBOM読み込み
    with open(sbom_file, encoding="utf-8") as f:
        sbom = json.load(f)

    # pipenv graph --json 読み込み
    with open(pipenv_graph_file, encoding="utf-8") as f:
        graph = json.load(f)

    # パッケージ名→SPDXIDの辞書を作成
    name_to_spdxid = {pkg["name"]: pkg["SPDXID"] for pkg in sbom.get("packages", []) if "SPDXID" in pkg and "name" in pkg}

    # 依存関係を抽出してrelationshipsに追加
    relationships = sbom.get("relationships", [])
    for node in graph:
        parent = node["package"]["key"]
        parent_spdxid = name_to_spdxid.get(parent)
        for dep in node.get("dependencies", []):
            child = dep["key"]
            child_spdxid = name_to_spdxid.get(child)
            if parent_spdxid and child_spdxid:
                relationships.append({
                    "spdxElementId": parent_spdxid,
                    "relatedSpdxElement": child_spdxid,
                    "relationshipType": "DEPENDS_ON"
                })
    sbom["relationships"] = relationships

    # 上書き保存
    with open(sbom_file, "w", encoding="utf-8") as f:
        json.dump(sbom, f, ensure_ascii=False, indent=2)

def map_npm_ls_to_sbom(sbom_file: str, npm_ls_file: str) -> None:
    """
    npm ls --all --json の依存関係情報をSBOMのrelationshipsにマッピングする
    """
    # SBOM読み込み
    with open(sbom_file, encoding="utf-8") as f:
        sbom = json.load(f)

    # npm ls --all --json 読み込み
    with open(npm_ls_file, encoding="utf-8") as f:
        npm_tree = json.load(f)

    # パッケージ名→SPDXIDの辞書を作成
    name_to_spdxid = {pkg["name"]: pkg["SPDXID"] for pkg in sbom.get("packages", []) if "SPDXID" in pkg and "name" in pkg}

    relationships = sbom.get("relationships", [])

    def walk_dependencies(parent_name, deps):
        parent_spdxid = name_to_spdxid.get(parent_name)
        if not parent_spdxid or not deps:
            return
        for child_name, child_info in deps.items():
            child_spdxid = name_to_spdxid.get(child_name)
            if child_spdxid:
                relationships.append({
                    "spdxElementId": parent_spdxid,
                    "relatedSpdxElement": child_spdxid,
                    "relationshipType": "DEPENDS_ON"
                })
            # 再帰的に子の依存も辿る
            walk_dependencies(child_name, child_info.get("dependencies", {}))

    # ルートパッケージから依存関係を辿る
    root_name = npm_tree.get("name")
    walk_dependencies(root_name, npm_tree.get("dependencies", {}))

    sbom["relationships"] = relationships

    # 上書き保存
    with open(sbom_file, "w", encoding="utf-8") as f:
        json.dump(sbom, f, ensure_ascii=False, indent=2)

def main() -> None:
    """
    メイン処理
    1. CSVからパッケージリスト取得
    2. 各パッケージごとにSBOM生成
    3. PythonパッケージSBOMをマージ
    4. Node.jsパッケージSBOMをマージ
    5. 実行時間表示
    """
    start_time = time.time()
    packages: list[list[str]] = parse_csv(CSV_FILE)
    if not packages:
        logger.warning("No packages found in CSV file.")
        return

    total = len(packages)
    sys.stdout.write(f"\rパッケージ処理中: 0/{total} (0%)")
    sys.stdout.flush()
    for i, pkg in enumerate(packages, 1):
        # idx, language, name, version, url
        idx, language, name, version, url = pkg
        create_individual_sbom(idx, language, name, version, url)
        percent = int(i / total * 100)
        sys.stdout.write(f"\rパッケージ処理中: {i}/{total} ({percent}%)")
        sys.stdout.flush()
    print()

    merge_sbom_files(OUTPUT_DIR, os.path.join(OUTPUT_DIR, "python_packages.json"))
    merge_nodejs_sbom_files(OUTPUT_DIR, os.path.join(OUTPUT_DIR, "nodejs_packages.json"))
    merge_java_sbom_files(OUTPUT_DIR, os.path.join(OUTPUT_DIR, "java_packages.json"))

    elapsed = time.time() - start_time
    print(f"実行時間: {int(elapsed//60)}分{int(elapsed%60)}秒")

if __name__ == "__main__":
    main()
