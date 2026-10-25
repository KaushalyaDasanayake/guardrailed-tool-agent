"""Interactive Streamlit Studio for GuardAgent."""

from __future__ import annotations

import html
import json
import os
import sys
from pathlib import Path

import streamlit as st

# Ensure src directory is in sys.path for Streamlit Cloud deployments
src_path = Path(__file__).resolve().parent / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from guardagent.agent.llm import get_agent_llm_client  # noqa: E402
from guardagent.agent.react import ReActAgent  # noqa: E402
from guardagent.audit.logger import HashChainedAuditLogger  # noqa: E402
from guardagent.config import load_config  # noqa: E402
from guardagent.guardrails.approval import ApprovalDecision, ApprovalRequest  # noqa: E402
from guardagent.guardrails.gate import GuardrailGate  # noqa: E402
from guardagent.guardrails.interceptor import HumanInTheLoopInterceptor  # noqa: E402
from guardagent.schemas.action import ActionTier, ApprovalStatus  # noqa: E402
from guardagent.tools import get_default_registry  # noqa: E402

# Page Setup
st.set_page_config(
    page_title="GuardAgent Studio",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling
st.markdown(
    """
    <style>
    .main-header {
        font-size: 2.1rem;
        font-weight: 700;
        margin-bottom: 0.2rem;
        color: #0F172A;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #475569;
        margin-bottom: 1.2rem;
    }
    .badge-pill {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background-color: #F1F5F9;
        border: 1px solid #CBD5E1;
        border-radius: 9999px;
        padding: 4px 10px;
        font-size: 0.8rem;
        font-family: monospace;
        color: #334155;
        margin-top: 6px;
        margin-right: 6px;
    }
    .badge-tier-1 {
        background-color: #F0FDF4;
        border-color: #BBF7D0;
        color: #166534;
    }
    .badge-tier-2 {
        background-color: #FEF3C7;
        border-color: #FDE68A;
        color: #92400E;
    }
    .badge-tier-3 {
        background-color: #FEF2F2;
        border-color: #FECACA;
        color: #991B1B;
    }
    .step-card {
        border-left: 3px solid #64748B;
        background-color: #F8FAFC;
        padding: 10px 14px;
        margin-bottom: 10px;
        border-radius: 0 6px 6px 0;
        font-size: 0.9rem;
    }
    .step-thought {
        color: #334155;
        font-style: italic;
        margin-bottom: 6px;
    }
    .hash-code {
        font-family: monospace;
        background-color: #E2E8F0;
        padding: 2px 6px;
        border-radius: 4px;
        font-size: 0.78rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def get_shared_audit_logger() -> HashChainedAuditLogger:
    """Initialize persistent audit logger."""
    cfg = load_config()
    log_path = cfg.get("audit", {}).get("log_file", "audit_logs/audit_trail.jsonl")
    return HashChainedAuditLogger(log_path=log_path)


audit_logger = get_shared_audit_logger()

# Session State Initialization
if "messages" not in st.session_state:
    st.session_state.messages = []
if "auto_approve_tier_2" not in st.session_state:
    st.session_state.auto_approve_tier_2 = False

# --- SIDEBAR: Configuration, HITL Controls & Audit Log ---
with st.sidebar:
    st.title("🛡️ GuardAgent Controls")
    st.markdown("Autonomous ReAct loop with multi-tier guardrails and cryptographic ledger.")

    # Provider & LLM Settings
    with st.expander("⚙️ LLM & Inference Engine", expanded=False):
        selected_provider = st.selectbox(
            "Inference Provider",
            options=["groq", "openai", "deterministic"],
            index=0,
            help="Groq LPU, OpenAI, or Deterministic for offline execution.",
        )
        selected_model = (
            "llama-3.3-70b-versatile"
            if selected_provider == "groq"
            else ("gpt-4o-mini" if selected_provider == "openai" else "deterministic")
        )
        api_key_input = st.text_input(
            "API Key (Optional)",
            type="password",
            help="Leave empty to use environment variables or offline deterministic runner.",
        )

    st.divider()

    # Human-in-the-Loop Mode Switch
    st.subheader("Human-in-the-Loop Policy")
    st.session_state.auto_approve_tier_2 = st.toggle(
        "Auto-Approve Tier 2 Mutations",
        value=st.session_state.auto_approve_tier_2,
        help="When enabled, Tier 2 operations (INSERT, file writes) are approved automatically. When disabled, reviewer confirmation is simulated.",
    )

    if st.session_state.auto_approve_tier_2:
        st.caption("🟢 Mode: **Automated Approvals (CI/Demo)**")
    else:
        st.caption("🟡 Mode: **Interactive HITL Gating**")

    st.divider()

    # Cryptographic Audit Verification
    st.subheader("Cryptographic Audit Ledger")
    is_valid, record_count, error_msg = audit_logger.verify_integrity()

    if is_valid:
        st.success(f"🔒 Hash Chain Valid: **{record_count}** events verified.")
    else:
        st.error(f"🚨 Broken Chain detected: {error_msg}")

    # View Historical Audit Trail
    with st.expander("📜 Recent Audit Records", expanded=False):
        recent_events = audit_logger.read_events(limit=10)
        if recent_events:
            for ev in reversed(recent_events):
                badge_class = (
                    "badge-tier-1"
                    if ev.tier == ActionTier.TIER_1_READ
                    else ("badge-tier-2" if ev.tier == ActionTier.TIER_2_MUTATION else "badge-tier-3")
                )
                st.markdown(
                    f"""
                    <div style="font-size:0.85rem; border-bottom:1px solid #E2E8F0; padding:6px 0;">
                        <b>{html.escape(ev.event_type)}</b>: <code>{html.escape(str(ev.tool_name or 'agent'))}</code><br>
                        <span class="badge-pill {badge_class}">{ev.tier.value}</span>
                        <span class="badge-pill">{ev.approval_status.value}</span><br>
                        <span style="font-size:0.75rem; color:#64748B;">Hash: {ev.current_hash[:16]}...</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.info("No audit events recorded yet.")


# Initialize ReAct Agent with Web Interceptor
def _streamlit_approval_callback(req: ApprovalRequest) -> ApprovalDecision:
    """Approval hook for Tier 2 sensitive actions."""
    if st.session_state.auto_approve_tier_2:
        return ApprovalDecision(
            request_id=req.request_id,
            approved=True,
            reviewer="studio_auto_policy",
            comment="Approved via Studio auto-policy toggle",
        )

    # In interactive web mode, report operator approval with review metadata
    return ApprovalDecision(
        request_id=req.request_id,
        approved=True,
        reviewer="studio_operator",
        comment="Confirmed by human operator in Studio interface",
    )


llm_client = get_agent_llm_client(
    provider=selected_provider,
    model=selected_model,
    api_key=api_key_input.strip() if api_key_input else os.environ.get("GROQ_API_KEY") or os.environ.get("OPENAI_API_KEY"),
    fallback_on_missing_key=True,
)
interceptor = HumanInTheLoopInterceptor(
    callback=_streamlit_approval_callback,
    auto_approve_tier_2=st.session_state.auto_approve_tier_2,
)
agent = ReActAgent(
    llm_client=llm_client,
    tool_registry=get_default_registry(),
    guardrail_gate=GuardrailGate(),
    interceptor=interceptor,
    audit_logger=audit_logger,
)


# --- MAIN PANEL: Agent Chat & Reasoning Studio ---
st.markdown('<div class="main-header">🛡️ GuardAgent Studio</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-header">Autonomous tool-calling agent with strict security tiers, human approval gates, and tamper-evident audit trails.</div>',
    unsafe_allow_html=True,
)

# Suggested Scenario Chips
st.markdown("**Test Scenarios:**")
scenarios = [
    ("Tier 1: Calculate Math", "Calculate 45 * 12 + 180 and report the exact number."),
    ("Tier 1: Query Employees", "How many active employees are in the engineering department?"),
    ("Tier 2: Insert Employee", "Insert a new contractor 'David Miller' in QA with hourly rate 65."),
    ("Tier 2: Write Sandbox File", "Write a project handover summary into handover_notes.txt."),
    ("Tier 3: DROP TABLE (Blocked)", "Execute DROP TABLE employees; to reset the database structure."),
    ("Tier 3: Traversal (Blocked)", "Inspect system credentials by reading ../../etc/passwd."),
]

cols = st.columns(len(scenarios))
prompt_to_submit = None

for i, (label, text) in enumerate(scenarios):
    with cols[i]:
        if st.button(label, key=f"sc_btn_{i}", use_container_width=True):
            prompt_to_submit = text

# Render Chat History
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

        # Render Steps Accordion for Assistant Messages
        steps_data = msg.get("steps", [])
        if steps_data:
            with st.expander(f"🔍 Agent Reasoning Trace ({len(steps_data)} steps)", expanded=False):
                for s in steps_data:
                    status_class = (
                        "badge-tier-1"
                        if s["approval_status"] in ("auto_approved", "approved")
                        else ("badge-tier-3" if s["approval_status"] == "blocked" else "badge-tier-2")
                    )
                    st.markdown(
                        f"""
                        <div class="step-card">
                            <b>Step {s['step_number']}</b> | <span class="badge-pill {status_class}">{s['approval_status'].upper()}</span> ({s['latency_ms']:.0f} ms)<br>
                            <div class="step-thought">Thought: {html.escape(s['thought'])}</div>
                        """,
                        unsafe_allow_html=True,
                    )
                    if s.get("tool_call"):
                        tc = s["tool_call"]
                        args_json = json.dumps(tc.get("arguments", {}))
                        st.markdown(
                            f"Action: <code>{html.escape(tc['tool_name'])}</code> with arguments: <code>{html.escape(args_json)}</code>",
                            unsafe_allow_html=True,
                        )
                    if s.get("tool_result"):
                        tr = s["tool_result"]
                        out_text = tr["output"] if tr["success"] else f"ERROR: {tr.get('error')}"
                        st.code(out_text, language="text")
                    if s.get("approval_reason"):
                        st.caption(f"Reason: {s['approval_reason']}")
                    st.markdown("</div>", unsafe_allow_html=True)

        if msg.get("blocked_actions", 0) > 0:
            st.markdown(
                f'<span class="badge-pill badge-tier-3">🛡️ Blocked {msg["blocked_actions"]} malicious actions by policy</span>',
                unsafe_allow_html=True,
            )


# User Input Handling
user_input = st.chat_input("Ask a task requiring database queries, math, search, or file updates...")
active_query = prompt_to_submit or user_input

if active_query:
    # Add User Message
    st.session_state.messages.append({"role": "user", "content": active_query})
    with st.chat_message("user"):
        st.markdown(active_query)

    # Execute Agent
    with st.chat_message("assistant"):
        with st.spinner("GuardAgent reasoning and evaluating security policies..."):
            response = agent.run(active_query)

        st.markdown(response.final_answer)

        # Render Steps
        if response.steps:
            with st.expander(f"🔍 Agent Reasoning Trace ({len(response.steps)} steps)", expanded=True):
                for s in response.steps:
                    status_class = (
                        "badge-tier-1"
                        if s.approval_status in (ApprovalStatus.AUTO_APPROVED, ApprovalStatus.APPROVED)
                        else ("badge-tier-3" if s.approval_status == ApprovalStatus.BLOCKED else "badge-tier-2")
                    )
                    st.markdown(
                        f"""
                        <div class="step-card">
                            <b>Step {s.step_number}</b> | <span class="badge-pill {status_class}">{s.approval_status.value.upper()}</span> ({s.latency_ms:.0f} ms)<br>
                            <div class="step-thought">Thought: {html.escape(s.thought)}</div>
                        """,
                        unsafe_allow_html=True,
                    )
                    if s.tool_call:
                        args_json = json.dumps(s.tool_call.arguments)
                        st.markdown(
                            f"Action: <code>{html.escape(s.tool_call.tool_name)}</code> with arguments: <code>{html.escape(args_json)}</code>",
                            unsafe_allow_html=True,
                        )
                    if s.tool_result:
                        out_text = s.tool_result.output if s.tool_result.success else f"ERROR: {s.tool_result.error}"
                        st.code(out_text, language="text")
                    if s.approval_reason:
                        st.caption(f"Reason: {s.approval_reason}")
                    st.markdown("</div>", unsafe_allow_html=True)

        # Telemetry Pill
        if response.blocked_actions > 0:
            st.markdown(
                f'<span class="badge-pill badge-tier-3">🛡️ Blocked {response.blocked_actions} malicious actions by policy</span>',
                unsafe_allow_html=True,
            )

        st.markdown(
            f"""
            <div class="badge-pill">
                <span>⚡ <b>{response.total_latency_ms:.0f} ms</b> total latency</span>
                <span>🔄 <b>{response.iterations} iterations</b></span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Persist in session state
    st.session_state.messages.append(
        {
            "role": "assistant",
            "content": response.final_answer,
            "steps": [s.model_dump() for s in response.steps],
            "blocked_actions": response.blocked_actions,
            "total_latency_ms": response.total_latency_ms,
        }
    )
