import json
import re
import tomllib
from dataclasses import dataclass
from typing import List


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: str
    file_path: str
    is_dev: bool = False
    is_pinned: bool = True
    raw_version: str = ""


class DependencyParser:
    MANIFEST_FILES = {
        "npm": ["package.json", "package-lock.json", "yarn.lock"],
        "pypi": [
            "requirements.txt",
            "requirements-dev.txt",
            "pyproject.toml",
            "poetry.lock",
            "setup.py",
        ],
        "cargo": ["Cargo.toml", "Cargo.lock"],
        "go": ["go.mod", "go.sum"],
        "maven": ["pom.xml"],
    }

    LOCKFILES = {
        "package-lock.json",
        "yarn.lock",
        "poetry.lock",
        "Cargo.lock",
        "go.sum",
    }

    @staticmethod
    def _is_version_pinned(version_spec: str) -> bool:
        if not version_spec:
            return False
        return not any(version_spec.startswith(op) for op in ("^", "~", ">", "<", "="))

    @staticmethod
    def parse_package_lock_json(content: str, file_path: str) -> List[Dependency]:
        deps = []
        try:
            data = json.loads(content)

            if "packages" in data:
                for package_path, package_info in data["packages"].items():
                    if package_path == "":
                        continue

                    name = package_path.replace("node_modules/", "")
                    version = package_info.get("version", "")
                    is_dev = package_info.get("dev", False)

                    if name and version:
                        deps.append(
                            Dependency(
                                name=name,
                                version=version,
                                ecosystem="npm",
                                file_path=file_path,
                                is_dev=is_dev,
                                is_pinned=True,
                            )
                        )

            # package-lock.json v1 format (legacy)
            elif "dependencies" in data:

                def extract_deps(deps_dict, is_dev_dep=False):
                    for name, info in deps_dict.items():
                        version = info.get("version", "")
                        if version:
                            deps.append(
                                Dependency(
                                    name=name,
                                    version=version,
                                    ecosystem="npm",
                                    file_path=file_path,
                                    is_dev=is_dev_dep,
                                    is_pinned=True,
                                )
                            )
                        if "dependencies" in info:
                            extract_deps(info["dependencies"], is_dev_dep)

                extract_deps(data["dependencies"])
        except Exception:
            pass

        return deps

    @staticmethod
    def parse_package_json(content: str, file_path: str) -> List[Dependency]:
        deps = []
        try:
            data = json.loads(content)

            if "dependencies" in data:
                for name, version in data["dependencies"].items():
                    if not version.startswith(("file:", "git+", "http:", "https:")):
                        is_pinned = DependencyParser._is_version_pinned(version)
                        clean_version = version.lstrip("^~>=<")
                        deps.append(
                            Dependency(
                                name=name,
                                version=clean_version,
                                ecosystem="npm",
                                file_path=file_path,
                                is_dev=False,
                                is_pinned=is_pinned,
                                raw_version=version,
                            )
                        )

            if "devDependencies" in data:
                for name, version in data["devDependencies"].items():
                    if not version.startswith(("file:", "git+", "http:", "https:")):
                        is_pinned = DependencyParser._is_version_pinned(version)
                        clean_version = version.lstrip("^~>=<")
                        deps.append(
                            Dependency(
                                name=name,
                                version=clean_version,
                                ecosystem="npm",
                                file_path=file_path,
                                is_dev=True,
                                is_pinned=is_pinned,
                                raw_version=version,
                            )
                        )
        except Exception:
            pass

        return deps

    @staticmethod
    def parse_requirements_txt(content: str, file_path: str) -> List[Dependency]:
        deps = []
        is_dev = "dev" in file_path.lower()

        for line in content.splitlines():
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if line.startswith(("git+", "http:", "https:", "-e")):
                continue

            match = re.match(r"^([a-zA-Z0-9_\-\[\]]+)([=<>!~]+)?(.+)?", line)
            if match:
                name = match.group(1)
                operator = match.group(2) if match.group(2) else ""
                version = match.group(3).strip() if match.group(3) else ""

                is_pinned = operator == "==" or not operator
                raw_version = f"{operator}{version}" if operator else version
                deps.append(
                    Dependency(
                        name=name,
                        version=version,
                        ecosystem="pypi",
                        file_path=file_path,
                        is_dev=is_dev,
                        is_pinned=is_pinned,
                        raw_version=raw_version,
                    )
                )

        return deps

    @staticmethod
    def parse_poetry_lock(content: str, file_path: str) -> List[Dependency]:
        deps = []
        try:
            data = tomllib.loads(content)

            if "package" in data:
                for pkg in data["package"]:
                    name = pkg.get("name", "")
                    version = pkg.get("version", "")
                    category = pkg.get("category", "main")

                    if name and version:
                        deps.append(
                            Dependency(
                                name=name,
                                version=version,
                                ecosystem="pypi",
                                file_path=file_path,
                                is_dev=category == "dev",
                                is_pinned=True,
                            )
                        )
        except Exception:
            pass

        return deps

    @staticmethod
    def parse_pyproject_toml(content: str, file_path: str) -> List[Dependency]:
        deps = []
        try:
            data = tomllib.loads(content)

            if "project" in data and "dependencies" in data["project"]:
                for dep_spec in data["project"]["dependencies"]:
                    match = re.match(
                        r"^([a-zA-Z0-9_\-\[\]]+)([=<>!~]+)?(.+)?", dep_spec
                    )
                    if match:
                        name = match.group(1)
                        operator = match.group(2) if match.group(2) else ""
                        version = match.group(3).strip() if match.group(3) else ""
                        is_pinned = operator == "==" or not operator
                        raw_version = f"{operator}{version}" if operator else version
                        deps.append(
                            Dependency(
                                name=name,
                                version=version,
                                ecosystem="pypi",
                                file_path=file_path,
                                is_dev=False,
                                is_pinned=is_pinned,
                                raw_version=raw_version,
                            )
                        )

            if "tool" in data and "poetry" in data["tool"]:
                poetry = data["tool"]["poetry"]

                if "dependencies" in poetry:
                    for name, spec in poetry["dependencies"].items():
                        if name == "python":
                            continue
                        version = ""
                        version_spec = ""
                        if isinstance(spec, str):
                            version_spec = spec
                            version = spec.lstrip("^~>=<")
                        elif isinstance(spec, dict) and "version" in spec:
                            version_spec = spec["version"]
                            version = spec["version"].lstrip("^~>=<")

                        is_pinned = (
                            DependencyParser._is_version_pinned(version_spec)
                            if version_spec
                            else True
                        )
                        deps.append(
                            Dependency(
                                name=name,
                                version=version,
                                ecosystem="pypi",
                                file_path=file_path,
                                is_dev=False,
                                is_pinned=is_pinned,
                                raw_version=version_spec if version_spec else version,
                            )
                        )

                if "dev-dependencies" in poetry:
                    for name, spec in poetry["dev-dependencies"].items():
                        version = ""
                        version_spec = ""
                        if isinstance(spec, str):
                            version_spec = spec
                            version = spec.lstrip("^~>=<")
                        elif isinstance(spec, dict) and "version" in spec:
                            version_spec = spec["version"]
                            version = spec["version"].lstrip("^~>=<")

                        is_pinned = (
                            DependencyParser._is_version_pinned(version_spec)
                            if version_spec
                            else True
                        )
                        deps.append(
                            Dependency(
                                name=name,
                                version=version,
                                ecosystem="pypi",
                                file_path=file_path,
                                is_dev=True,
                                is_pinned=is_pinned,
                                raw_version=version_spec if version_spec else version,
                            )
                        )
        except Exception:
            pass

        return deps

    @staticmethod
    def parse_cargo_lock(content: str, file_path: str) -> List[Dependency]:
        deps = []
        try:
            data = tomllib.loads(content)

            if "package" in data:
                for pkg in data["package"]:
                    name = pkg.get("name", "")
                    version = pkg.get("version", "")

                    if name and version:
                        deps.append(
                            Dependency(
                                name=name,
                                version=version,
                                ecosystem="cargo",
                                file_path=file_path,
                                is_dev=False,
                                is_pinned=True,
                            )
                        )
        except Exception:
            pass

        return deps

    @staticmethod
    def parse_cargo_toml(content: str, file_path: str) -> List[Dependency]:
        deps = []
        try:
            data = tomllib.loads(content)

            if "dependencies" in data:
                for name, spec in data["dependencies"].items():
                    if isinstance(spec, dict):
                        if "path" in spec or "git" in spec:
                            continue
                        version_spec = spec.get("version", "")
                    else:
                        version_spec = str(spec)

                    is_pinned = DependencyParser._is_version_pinned(version_spec)
                    version = version_spec.lstrip("^~>=<")
                    deps.append(
                        Dependency(
                            name=name,
                            version=version,
                            ecosystem="cargo",
                            file_path=file_path,
                            is_dev=False,
                            is_pinned=is_pinned,
                            raw_version=version_spec,
                        )
                    )

            if "dev-dependencies" in data:
                for name, spec in data["dev-dependencies"].items():
                    if isinstance(spec, dict):
                        if "path" in spec or "git" in spec:
                            continue
                        version_spec = spec.get("version", "")
                    else:
                        version_spec = str(spec)

                    is_pinned = DependencyParser._is_version_pinned(version_spec)
                    version = version_spec.lstrip("^~>=<")
                    deps.append(
                        Dependency(
                            name=name,
                            version=version,
                            ecosystem="cargo",
                            file_path=file_path,
                            is_dev=True,
                            is_pinned=is_pinned,
                            raw_version=version_spec,
                        )
                    )
        except Exception:
            pass

        return deps

    @staticmethod
    def parse_go_mod(content: str, file_path: str) -> List[Dependency]:
        deps = []
        in_require = False

        for line in content.splitlines():
            line = line.strip()

            if line.startswith("require ("):
                in_require = True
                continue
            elif line == ")":
                in_require = False
                continue

            if line.startswith("require ") or in_require:
                parts = line.replace("require ", "").split()
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1].lstrip("v")
                    deps.append(
                        Dependency(
                            name=name,
                            version=version,
                            ecosystem="go",
                            file_path=file_path,
                            is_dev=False,
                            is_pinned=True,
                        )
                    )

        return deps

    @staticmethod
    def parse_pom_xml(content: str, file_path: str) -> List[Dependency]:
        deps = []

        dep_pattern = re.compile(
            r"<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>.*?</dependency>",
            re.DOTALL,
        )

        for match in dep_pattern.finditer(content):
            group_id = match.group(1).strip()
            artifact_id = match.group(2).strip()
            version = match.group(3).strip()

            if not version.startswith("${"):
                name = f"{group_id}:{artifact_id}"
                deps.append(
                    Dependency(
                        name=name,
                        version=version,
                        ecosystem="maven",
                        file_path=file_path,
                        is_dev=False,
                        is_pinned=True,
                    )
                )

        return deps

    @classmethod
    def parse_file(cls, file_path: str, content: str) -> List[Dependency]:
        file_name = file_path.split("/")[-1]

        if file_name == "package-lock.json":
            return cls.parse_package_lock_json(content, file_path)
        elif file_name == "poetry.lock":
            return cls.parse_poetry_lock(content, file_path)
        elif file_name == "Cargo.lock":
            return cls.parse_cargo_lock(content, file_path)
        elif file_name == "package.json":
            return cls.parse_package_json(content, file_path)
        elif file_name.startswith("requirements") and file_name.endswith(".txt"):
            return cls.parse_requirements_txt(content, file_path)
        elif file_name == "pyproject.toml":
            return cls.parse_pyproject_toml(content, file_path)
        elif file_name == "Cargo.toml":
            return cls.parse_cargo_toml(content, file_path)
        elif file_name == "go.mod":
            return cls.parse_go_mod(content, file_path)
        elif file_name == "pom.xml":
            return cls.parse_pom_xml(content, file_path)

        return []

    @classmethod
    def get_all_manifest_patterns(cls) -> List[str]:
        patterns = []
        for files in cls.MANIFEST_FILES.values():
            patterns.extend(files)
        return patterns
