# 🔐 DkWess SecureRepo v1.0.0 — Guia em Português

SecureRepo é uma ferramenta Python local para auditoria defensiva de repositórios. Ela analisa governança, higiene do repositório, nomes/caminhos sensíveis, dependências e padrões de risco em GitHub Actions sem executar o código do projeto auditado.

> **Regra central:** `PASS != SECURITY GUARANTEE`.

## 🚀 Instalação no Windows

```powershell
git clone https://github.com/DKWesley13/DkWess.git
cd DkWess
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
dkwess-securerepo --version
dkwess-securerepo .
```

## 🐧 Linux / macOS

```bash
git clone https://github.com/DKWesley13/DkWess.git
cd DkWess
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
dkwess-securerepo .
```

Os relatórios padrão ficam em `reports/audit.json` e `reports/audit.md`.

## 🧭 Para que serve

- verificar arquivos de governança e documentação;
- revisar `.gitignore` e descoberta do repositório;
- sinalizar nomes/caminhos normalmente associados a credenciais sem imprimir o conteúdo secreto;
- inventariar manifests e verificar alguns lockfiles;
- revisar padrões de risco em workflows do GitHub Actions;
- gerar evidências com severidade, confiança, fingerprint, assessment e coverage;
- criar baseline de problemas conhecidos e detectar regressões novas;
- gerar inventário de supply chain e evidência local de provenance;
- exportar SARIF 2.1.0;
- gerar inventário SBOM CycloneDX 1.5 de forma estática e best-effort;
- aplicar política TOML/JSON;
- avaliar readiness técnico da versão 1.

## 🧪 Comandos úteis

```bash
dkwess-securerepo --list-checks
dkwess-securerepo --explain SR-GHA-010
dkwess-securerepo . --fail-on MEDIUM
dkwess-securerepo . --require-full-coverage
dkwess-securerepo --show-limits
```

### Baseline

```bash
dkwess-securerepo . --write-baseline .securerepo-baseline.json
dkwess-securerepo . --compare-baseline .securerepo-baseline.json --fail-on HIGH --fail-on-new
```

Problemas já presentes continuam aparecendo no relatório. A baseline não transforma problema em `PASS`.

### Supply chain + SARIF + SBOM

```bash
dkwess-securerepo . \
  --supply-chain reports/supply-chain.json \
  --provenance reports/provenance.json \
  --sarif reports/securerepo.sarif \
  --sbom reports/sbom.cdx.json
```

### Política

```toml
[policy]
fail_on = "HIGH"
require_full_coverage = false
disabled_rules = []
exclude_paths = []
allow_critical_suppression = false
```

```bash
dkwess-securerepo . --policy securerepo.toml
```

### Readiness da release

```bash
dkwess-securerepo . --release-check
```

O SecureRepo separa `technical_ready` de `open_source_reuse_ready`. Isso é proposital: um projeto pode estar tecnicamente estável e ainda não ter uma licença que autorize reutilização.

## 📊 Como interpretar

`PASS`, `FAIL`, `BLOCKED` e `NOT_ASSESSED` descrevem o assessment. `FULL`, `PARTIAL` e `UNKNOWN` descrevem o alcance dos checks implementados. Nenhum desses estados significa garantia absoluta de segurança.

## 🛡 Segurança do próprio scanner

A API pública usa limites de pré-validação, não segue symlinks durante descoberta, não executa código do repositório auditado e mantém runtime somente com biblioteca padrão do Python. O CI do projeto roda em Linux, macOS e Windows.

## 📚 Documentação

Comece por [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md) e [`docs/USAGE.md`](docs/USAGE.md). Depois consulte `CHECKS`, `BASELINES`, `SUPPLY_CHAIN`, `SARIF`, `SBOM`, `POLICY`, `HARDENING`, `THREAT_MODEL` e `V1_AUDIT` dentro de `docs/`.

## ⚖️ Licença

A licença de software ainda não foi escolhida. O código está público, mas visibilidade pública por si só não concede permissão geral de reutilização ou redistribuição. A escolha da licença continua sendo uma decisão explícita do mantenedor.
