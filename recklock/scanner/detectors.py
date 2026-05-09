"""Static signal detectors for the ReckLock Discover.

Detectors are deterministic regex / substring matchers. No LLM calls,
no network calls. Each detector emits ``ScannerSignal`` rows that the
classifier later turns into a finding type, risk level, & recommendation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from recklock.scanner.models import ScannerSignal
from recklock.scanner.redaction import redact_snippet

# --- Categories used across detectors -----------------------------------------------------
CAT_LLM = "llm_ai"
CAT_OUTBOUND = "outbound"
CAT_BROWSER = "browser_or_http"
CAT_DEPLOY = "deploy_infra"
CAT_DATABASE = "database"
CAT_PAYMENTS = "payments_financial"
CAT_SECRETS = "secrets"
CAT_SCHEDULE = "schedule"
CAT_SHELL = "shell_execution"
CAT_CI_CD = "ci_cd"
CAT_FILE = "file_marker"


@dataclass(frozen=True)
class ContentDetector:
    """Detector that runs a regex against file content."""

    name: str
    category: str
    pattern: re.Pattern[str]
    description: str = ""


def _ci(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# --- LLM / AI -----------------------------------------------------------------------------
LLM_DETECTORS: tuple[ContentDetector, ...] = (
    ContentDetector(
        "imports or calls OpenAI",
        CAT_LLM,
        _ci(
            r"\b(import\s+openai\b|from\s+openai\b|require\(['\"]openai['\"]\)|"
            r"openai\.[A-Za-z_]+\s*\(|OpenAI\s*\(|api\.openai\.com)"
        ),
    ),
    ContentDetector(
        "imports or calls Anthropic",
        CAT_LLM,
        _ci(
            r"\b(import\s+anthropic\b|from\s+anthropic\b|require\(['\"]@?anthropic[^'\"]*['\"]\)|"
            r"Anthropic\s*\(|api\.anthropic\.com)"
        ),
    ),
    ContentDetector(
        "uses Google Generative AI / Gemini",
        CAT_LLM,
        _ci(
            r"\b(google\.generativeai|google\.ai\.generativelanguage|generativeai|"
            r"@google/generative-ai|vertexai\b|aiplatform\b|gemini\b)"
        ),
    ),
    ContentDetector(
        "uses LangChain / LangGraph",
        CAT_LLM,
        _ci(r"\b(langchain\b|langgraph\b)"),
    ),
    ContentDetector("uses CrewAI", CAT_LLM, _ci(r"\bcrewai\b")),
    ContentDetector("uses AutoGen", CAT_LLM, _ci(r"\b(pyautogen|autogen-?agentchat|\bautogen\b)")),
    ContentDetector("uses LlamaIndex", CAT_LLM, _ci(r"\b(llama_index|llamaindex)\b")),
    ContentDetector("uses Ollama", CAT_LLM, _ci(r"\bollama\b|api/generate")),
    ContentDetector("uses LiteLLM", CAT_LLM, _ci(r"\blitellm\b")),
    ContentDetector("uses Instructor (function calling)", CAT_LLM, _ci(r"\binstructor\b")),
    ContentDetector(
        "uses Semantic Kernel",
        CAT_LLM,
        _ci(r"\bsemantic_kernel\b|semantic-kernel"),
    ),
    ContentDetector(
        "tool calling / function calling",
        CAT_LLM,
        _ci(
            r"\b(tool_calls?|tool_call_id|function_call|function_calling|"
            r"tools\s*=\s*\[|tool_choice)\b"
        ),
    ),
    ContentDetector(
        "agent framework reference",
        CAT_LLM,
        _ci(r"\b(agents?\.run\(|\bAgentExecutor\b|\bopenai-agents\b)"),
    ),
)

# --- Outbound / comms ---------------------------------------------------------------------
OUTBOUND_DETECTORS: tuple[ContentDetector, ...] = (
    ContentDetector(
        "smtplib / SMTP / EmailMessage",
        CAT_OUTBOUND,
        _ci(r"\b(smtplib\b|EmailMessage|MIMEText|smtp\.send_message|send_email|send_mail)\b"),
    ),
    ContentDetector("SendGrid usage", CAT_OUTBOUND, _ci(r"\b(sendgrid\b|api\.sendgrid\.com)")),
    ContentDetector("Postmark usage", CAT_OUTBOUND, _ci(r"\b(postmark\b|api\.postmarkapp\.com)")),
    ContentDetector("Resend usage", CAT_OUTBOUND, _ci(r"\b(resend\b|api\.resend\.com)")),
    ContentDetector("Mailgun usage", CAT_OUTBOUND, _ci(r"\b(mailgun\b|api\.mailgun\.net)")),
    ContentDetector(
        "Slack SDK / webhook",
        CAT_OUTBOUND,
        _ci(r"\b(slack_sdk\b|@slack/web-api|hooks\.slack\.com|slack_webhook)"),
    ),
    ContentDetector(
        "Discord webhook / SDK",
        CAT_OUTBOUND,
        _ci(r"\b(discord\.py\b|discord\.js\b|discordapp\.com|discord\.com/api/webhooks)"),
    ),
    ContentDetector(
        "Twilio SDK / API",
        CAT_OUTBOUND,
        _ci(r"\b(twilio\b|api\.twilio\.com)"),
    ),
    ContentDetector(
        "generic outbound webhook",
        CAT_OUTBOUND,
        _ci(r"\bwebhook(?:s)?\b|hooks/[A-Z0-9]"),
    ),
)

# --- Browser / HTTP -----------------------------------------------------------------------
BROWSER_DETECTORS: tuple[ContentDetector, ...] = (
    ContentDetector(
        "Playwright automation",
        CAT_BROWSER,
        _ci(r"\b(from\s+playwright|require\(['\"]playwright['\"]\)|playwright\.(chromium|firefox|webkit))\b"),
    ),
    ContentDetector("Selenium automation", CAT_BROWSER, _ci(r"\bselenium\b|webdriver\.")),
    ContentDetector("Puppeteer automation", CAT_BROWSER, _ci(r"\bpuppeteer\b")),
    ContentDetector("browser-use library", CAT_BROWSER, _ci(r"browser[\-_]use")),
    ContentDetector(
        "Python requests HTTP client",
        CAT_BROWSER,
        _ci(r"\b(import\s+requests\b|from\s+requests\b|requests\.(get|post|put|delete|patch)\()"),
    ),
    ContentDetector(
        "httpx HTTP client",
        CAT_BROWSER,
        _ci(r"\b(import\s+httpx\b|from\s+httpx\b|httpx\.(get|post|put|delete|patch|AsyncClient|Client)\()"),
    ),
    ContentDetector(
        "aiohttp HTTP client",
        CAT_BROWSER,
        _ci(r"\b(import\s+aiohttp\b|from\s+aiohttp\b|aiohttp\.ClientSession)"),
    ),
)

# --- Deploy / infra -----------------------------------------------------------------------
DEPLOY_DETECTORS: tuple[ContentDetector, ...] = (
    ContentDetector("Docker build / compose", CAT_DEPLOY, _ci(r"\b(docker\s+build|docker-compose\b|docker\s+compose)\b")),
    ContentDetector("kubectl invocation", CAT_DEPLOY, _ci(r"\bkubectl\b")),
    ContentDetector("Helm invocation", CAT_DEPLOY, _ci(r"\bhelm\s+(install|upgrade|template)\b")),
    ContentDetector("Terraform invocation", CAT_DEPLOY, _ci(r"\bterraform\s+(apply|plan|init|destroy)\b")),
    ContentDetector("Pulumi invocation", CAT_DEPLOY, _ci(r"\bpulumi\s+(up|preview|destroy|stack)\b")),
    ContentDetector("aws CLI invocation", CAT_DEPLOY, _ci(r"\baws\s+(s3|ec2|ecs|lambda|iam|sts|cloudformation|deploy)\b")),
    ContentDetector("boto3 SDK", CAT_DEPLOY, _ci(r"\b(boto3\b|botocore\b)")),
    ContentDetector("gcloud invocation", CAT_DEPLOY, _ci(r"\bgcloud\s+\w+")),
    ContentDetector("azure CLI invocation", CAT_DEPLOY, _ci(r"\baz\s+(account|deployment|webapp|vm|aks|storage|ad)\b")),
    ContentDetector("Vercel deploy", CAT_DEPLOY, _ci(r"\bvercel\b")),
    ContentDetector("Netlify deploy", CAT_DEPLOY, _ci(r"\bnetlify\b")),
    ContentDetector("Railway deploy", CAT_DEPLOY, _ci(r"\brailway\b")),
    ContentDetector("Fly.io flyctl", CAT_DEPLOY, _ci(r"\bflyctl\b|\bfly\s+deploy\b")),
    ContentDetector(
        "deploy / production keywords",
        CAT_DEPLOY,
        _ci(r"\b(deploy_to_production|deploy-prod|production_deploy|prod_deploy)\b"),
    ),
)

# --- Database -----------------------------------------------------------------------------
DATABASE_DETECTORS: tuple[ContentDetector, ...] = (
    ContentDetector("references DATABASE_URL", CAT_DATABASE, _ci(r"\bDATABASE_URL\b|\bPOSTGRES_URL\b|\bMYSQL_URL\b")),
    ContentDetector("psycopg driver", CAT_DATABASE, _ci(r"\bpsycopg2?\b")),
    ContentDetector("SQLAlchemy ORM", CAT_DATABASE, _ci(r"\b(sqlalchemy|SQLAlchemy)\b")),
    ContentDetector("Prisma ORM", CAT_DATABASE, _ci(r"@prisma/client|prisma\.\$?[a-zA-Z_]+\(")),
    ContentDetector("Supabase client", CAT_DATABASE, _ci(r"\bsupabase\b")),
    ContentDetector("Firebase / Firestore", CAT_DATABASE, _ci(r"\b(firebase|firestore)\b")),
    ContentDetector("Redis client", CAT_DATABASE, _ci(r"\bredis\.(?:Redis|StrictRedis|asyncio)\b|\bioredis\b|require\(['\"]redis['\"]\)")),
    ContentDetector(
        "database write operation",
        CAT_DATABASE,
        _ci(
            r"(INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|"
            r"\.execute\(\s*['\"]?(INSERT|UPDATE|DELETE)|"
            r"session\.add\(|session\.delete\(|session\.commit\(|"
            r"\.upsert\(|\.create\(|\.update\(|\.delete\()"
        ),
    ),
)

# --- Payments / financial -----------------------------------------------------------------
PAYMENT_DETECTORS: tuple[ContentDetector, ...] = (
    ContentDetector("Stripe SDK / API", CAT_PAYMENTS, _ci(r"\bstripe\b|api\.stripe\.com|STRIPE_(SECRET|API)_KEY")),
    ContentDetector("Plaid SDK / API", CAT_PAYMENTS, _ci(r"\bplaid\b|api\.plaid\.com")),
    ContentDetector("Dwolla SDK / API", CAT_PAYMENTS, _ci(r"\bdwolla\b|api\.dwolla\.com")),
    ContentDetector("PayPal SDK / API", CAT_PAYMENTS, _ci(r"\bpaypal\b|api\.paypal\.com|api-m\.paypal\.com")),
    ContentDetector(
        "banking / wallet / payment keyword",
        CAT_PAYMENTS,
        _ci(r"\b(banking|wallet|payment|payout|transfer|ach|kyc|aml)\b"),
    ),
    ContentDetector(
        "money movement verb",
        CAT_PAYMENTS,
        _ci(r"\b(initiate_transfer|create_payment|create_payout|charge_card|debit_account|credit_account)\b"),
    ),
)

# --- Secrets ------------------------------------------------------------------------------
SECRETS_DETECTORS: tuple[ContentDetector, ...] = (
    ContentDetector(
        "API key reference",
        CAT_SECRETS,
        _ci(r"\b[A-Z0-9_]*API_KEY[A-Z0-9_]*\b|\bAPI_KEYS?\b"),
    ),
    ContentDetector(
        "secret env var",
        CAT_SECRETS,
        _ci(r"\b[A-Z0-9_]*SECRET[A-Z0-9_]*\b|\bCLIENT_SECRET\b|\bJWT_SECRET\b|\bSIGNING_SECRET\b"),
    ),
    ContentDetector(
        "token env var",
        CAT_SECRETS,
        _ci(r"\b[A-Z0-9_]*TOKEN[A-Z0-9_]*\b|\bGITHUB_TOKEN\b|\bGH_TOKEN\b|\bSLACK_BOT_TOKEN\b|\bDISCORD_TOKEN\b"),
    ),
    ContentDetector("private key reference", CAT_SECRETS, _ci(r"PRIVATE_KEY|BEGIN [A-Z ]*PRIVATE KEY")),
    ContentDetector(
        "password env var",
        CAT_SECRETS,
        _ci(r"\b[A-Z0-9_]*PASSWORD[A-Z0-9_]*\b|\b[A-Z0-9_]*PASSWD[A-Z0-9_]*\b|\bPASSPHRASE\b|\bDB_PASSWORD\b"),
    ),
    ContentDetector(
        "Authorization / bearer header",
        CAT_SECRETS,
        _ci(r"(Authorization\s*[:=]\s*['\"]?Bearer\b|Bearer\s+[A-Za-z0-9_\-\.\=\+/]{8,})"),
    ),
    ContentDetector(
        "credentials artifact",
        CAT_SECRETS,
        _ci(r"\b(credentials\.json|service-account\.json|aws/credentials)\b"),
    ),
)

# --- Scheduling / background --------------------------------------------------------------
SCHEDULE_DETECTORS: tuple[ContentDetector, ...] = (
    ContentDetector("cron / crontab", CAT_SCHEDULE, _ci(r"\b(crontab|cron\b|cron-?expression)\b")),
    ContentDetector("schedule library", CAT_SCHEDULE, _ci(r"\b(schedule\.(every|run_pending)|node-schedule)\b")),
    ContentDetector("APScheduler", CAT_SCHEDULE, _ci(r"\bAPScheduler\b|apscheduler")),
    ContentDetector("Celery beat / task", CAT_SCHEDULE, _ci(r"\b(celery\b|@shared_task|celery\s+beat)\b")),
    ContentDetector("RQ background worker", CAT_SCHEDULE, _ci(r"\b(from\s+rq\b|import\s+rq\b|rq\s+worker)\b")),
    ContentDetector(
        "GitHub Actions schedule",
        CAT_SCHEDULE,
        _ci(r"on:\s*\n\s*schedule:|^\s*-\s*cron:\s*['\"]"),
    ),
    ContentDetector(
        "background worker keyword",
        CAT_SCHEDULE,
        _ci(r"\b(worker|queue|background_job|delayed_job)\b"),
    ),
)

# --- Shell execution ----------------------------------------------------------------------
SHELL_DETECTORS: tuple[ContentDetector, ...] = (
    ContentDetector(
        "subprocess invocation",
        CAT_SHELL,
        _ci(r"\b(subprocess\.(run|call|check_call|check_output|Popen)|from\s+subprocess|import\s+subprocess)\b"),
    ),
    ContentDetector("os.system call", CAT_SHELL, _ci(r"\bos\.system\s*\(")),
    ContentDetector("os.popen call", CAT_SHELL, _ci(r"\bos\.popen\s*\(|\bpopen\s*\(")),
    ContentDetector("Python exec()/eval()", CAT_SHELL, _ci(r"(?<![A-Za-z_])(exec|eval)\s*\(")),
    ContentDetector(
        "Node child_process / spawn",
        CAT_SHELL,
        _ci(r"\b(child_process\b|\bspawn\s*\(|\bexecSync\s*\(|\bexecFile\s*\()"),
    ),
)

# --- CI/CD --------------------------------------------------------------------------------
CI_CD_DETECTORS: tuple[ContentDetector, ...] = (
    ContentDetector(
        "GitHub Actions workflow body",
        CAT_CI_CD,
        _ci(r"^\s*jobs:\s*$|actions/checkout@|uses:\s*[A-Za-z0-9_./-]+@"),
    ),
)

ALL_CONTENT_DETECTORS: tuple[ContentDetector, ...] = (
    LLM_DETECTORS
    + OUTBOUND_DETECTORS
    + BROWSER_DETECTORS
    + DEPLOY_DETECTORS
    + DATABASE_DETECTORS
    + PAYMENT_DETECTORS
    + SECRETS_DETECTORS
    + SCHEDULE_DETECTORS
    + SHELL_DETECTORS
    + CI_CD_DETECTORS
)


# --- Filename / path-driven signals -------------------------------------------------------
def filename_signals(rel_posix: str, lower_name: str) -> list[ScannerSignal]:
    """Detectors that key off path/filename rather than file content."""
    out: list[ScannerSignal] = []

    if rel_posix.startswith(".github/workflows/") and lower_name.endswith((".yml", ".yaml")):
        out.append(
            ScannerSignal(
                name="GitHub Actions workflow file",
                category=CAT_CI_CD,
                line_number=None,
                redacted_snippet=None,
            )
        )

    if lower_name == "dockerfile" or lower_name.startswith("dockerfile."):
        out.append(
            ScannerSignal(
                name="Dockerfile present",
                category=CAT_DEPLOY,
                line_number=None,
                redacted_snippet=None,
            )
        )

    if lower_name in {"docker-compose.yml", "docker-compose.yaml"}:
        out.append(
            ScannerSignal(
                name="docker-compose file",
                category=CAT_DEPLOY,
                line_number=None,
                redacted_snippet=None,
            )
        )

    if lower_name in {"package.json", "pyproject.toml", "requirements.txt"}:
        out.append(
            ScannerSignal(
                name="dependency manifest",
                category=CAT_FILE,
                line_number=None,
                redacted_snippet=None,
            )
        )

    return out


def dependency_manifest_signals(text: str, lower_name: str) -> list[ScannerSignal]:
    """Detect AI / agent SDKs declared in dependency manifests."""
    if lower_name not in {"package.json", "pyproject.toml", "requirements.txt"}:
        return []
    blob = text.lower()
    out: list[ScannerSignal] = []

    deps_to_label = (
        ("openai", "dependency declares OpenAI SDK"),
        ("anthropic", "dependency declares Anthropic SDK"),
        ("@anthropic-ai", "dependency declares Anthropic SDK"),
        ("@google/generative-ai", "dependency declares Google Generative AI SDK"),
        ("google-generativeai", "dependency declares Google Generative AI SDK"),
        ("vertexai", "dependency declares Vertex AI SDK"),
        ("langchain", "dependency declares LangChain"),
        ("langgraph", "dependency declares LangGraph"),
        ("crewai", "dependency declares CrewAI"),
        ("autogen", "dependency declares AutoGen"),
        ("llama-index", "dependency declares LlamaIndex"),
        ("llama_index", "dependency declares LlamaIndex"),
        ("ollama", "dependency declares Ollama client"),
        ("litellm", "dependency declares LiteLLM"),
        ("instructor", "dependency declares Instructor"),
        ("semantic-kernel", "dependency declares Semantic Kernel"),
        ("playwright", "dependency declares Playwright"),
        ("selenium", "dependency declares Selenium"),
        ("puppeteer", "dependency declares Puppeteer"),
        ("browser-use", "dependency declares browser-use"),
        ("@slack/web-api", "dependency declares Slack SDK"),
        ("slack_sdk", "dependency declares Slack SDK"),
        ("stripe", "dependency declares Stripe SDK"),
        ("plaid", "dependency declares Plaid SDK"),
    )
    for needle, label in deps_to_label:
        if needle in blob:
            cat = CAT_LLM
            if "playwright" in needle or "selenium" in needle or "puppeteer" in needle or "browser-use" in needle:
                cat = CAT_BROWSER
            elif "slack" in needle:
                cat = CAT_OUTBOUND
            elif needle in {"stripe", "plaid"}:
                cat = CAT_PAYMENTS
            out.append(ScannerSignal(name=label, category=cat))

    seen: set[str] = set()
    deduped: list[ScannerSignal] = []
    for sig in out:
        if sig.name in seen:
            continue
        seen.add(sig.name)
        deduped.append(sig)
    return deduped


def detect_in_text(text: str) -> list[ScannerSignal]:
    """Run every content detector against *text* and return one signal per match."""
    if not text:
        return []
    lines = text.splitlines()
    out: list[ScannerSignal] = []
    seen: set[str] = set()

    for det in ALL_CONTENT_DETECTORS:
        match = det.pattern.search(text)
        if not match:
            continue
        line_no = text.count("\n", 0, match.start()) + 1
        line_text = lines[line_no - 1] if 0 <= line_no - 1 < len(lines) else match.group(0)
        snippet = redact_snippet(line_text)
        key = det.name
        if key in seen:
            continue
        seen.add(key)
        out.append(
            ScannerSignal(
                name=det.name,
                category=det.category,
                line_number=line_no,
                redacted_snippet=snippet,
            )
        )
    return out


def detect_signals_for_file(text: str | None, rel_posix: str, lower_name: str) -> list[ScannerSignal]:
    """Combine filename-driven and content-driven detectors for one file."""
    out: list[ScannerSignal] = list(filename_signals(rel_posix, lower_name))
    if text:
        out.extend(dependency_manifest_signals(text, lower_name))
        out.extend(detect_in_text(text))
    seen: set[str] = set()
    deduped: list[ScannerSignal] = []
    for sig in out:
        if sig.name in seen:
            continue
        seen.add(sig.name)
        deduped.append(sig)
    return deduped
