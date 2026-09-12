<div align="center">

# 🔐 DkWess SecureRepo

### Auditoria de segurança, governança e GitHub Actions orientada por evidências

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![Versão](https://img.shields.io/badge/versão-0.0.3-orange)
![Status](https://img.shields.io/badge/status-alpha-yellow)

[English](README.md) · [Começar](#-começando-do-zero) · [Comandos](#-comandos-principais) · [Documentação](#-documentação)

</div>

---

O **DkWess SecureRepo** é uma ferramenta Python para fazer uma primeira auditoria estruturada de um repositório de software. Ele procura sinais de risco e registra **o que realmente foi analisado**.

A regra mais importante é: **`PASS != SECURITY GUARANTEE`**.

## 🎯 Para que serve?
- 📘 documentação e governança;
- 🧹 `.gitignore` e higiene;
- 🔑 arquivos potencialmente sensíveis;
- 📦 manifests e alguns lockfiles;
- ⚙️ riscos comuns de GitHub Actions;
- 📊 cobertura da auditoria;
- 🧾 relatórios Markdown e JSON.

## 🚀 Começando do zero

### 1. Confirme Python 3.11+
```powershell
python --version
```

### 2. Clone
```powershell
git clone https://github.com/DKWesley13/DkWess.git
cd DkWess
```

### 3. Ambiente virtual no Windows
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

### 4. Confira
```powershell
dkwess-securerepo --version
```

### 5. Audite
```powershell
dkwess-securerepo "C:\Projetos\MeuProjeto"
```

Relatórios:
```text
reports/audit.md
reports/audit.json
```

## 🧰 Comandos principais
```powershell
dkwess-securerepo --list-checks
dkwess-securerepo --explain SR-GHA-007
dkwess-securerepo . --fail-on MEDIUM
dkwess-securerepo . --require-full-coverage
dkwess-securerepo . --no-reports --json-stdout
```

## 📊 Como interpretar
| Estado | Significado |
|---|---|
| `PASS` | checks implementados terminaram sem findings |
| `FAIL` | um ou mais findings |
| `BLOCKED` | análise tentou executar mas não terminou |
| `NOT_ASSESSED` | não há conclusão válida |

| Cobertura | Significado |
|---|---|
| `FULL` | checks implementados terminaram |
| `PARTIAL` | apenas parte terminou |
| `UNKNOWN` | a ferramenta não afirma cobertura suficiente |

## ⚙️ Melhorias da v0.0.3
- GitHub Actions Analyzer V2;
- contexto não confiável em shell;
- `curl/wget | bash/sh`;
- runners `self-hosted`;
- Docker actions sem digest;
- combinação crítica `pull_request_target` + código do PR;
- lockfile Node.js e Go;
- métricas e fingerprints;
- `--list-checks`, `--explain`, `--json-stdout`, `--require-full-coverage`;
- `action.yml` para integração no GitHub;
- documentação e tutorial ampliados.

## 📚 Documentação
- [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md)
- [`docs/USAGE.md`](docs/USAGE.md)
- [`docs/GITHUB_ACTIONS.md`](docs/GITHUB_ACTIONS.md)
- [`docs/AUDIT_METHODOLOGY.md`](docs/AUDIT_METHODOLOGY.md)
- [`docs/PROJECT_MAP.md`](docs/PROJECT_MAP.md)
- [`docs/FAQ.md`](docs/FAQ.md)

## ⚖️ Licença
A licença ainda precisa ser escolhida pelo mantenedor antes de tratarmos o projeto como open source plenamente reutilizável. Código público não substitui uma licença de software.
