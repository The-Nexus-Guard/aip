#!/usr/bin/env python3
"""
CrewAI + AIP Signed Workflow Example

Shows how to add cryptographic identity to CrewAI agents so that:
- Each agent has a verifiable DID
- Agent outputs are cryptographically signed
- Other agents can verify who produced what

Requirements:
    pip install aip-identity crewai langchain-core

Usage:
    python crewai_signed_workflow.py
"""

import json
from aip_identity.integrations.auto import ensure_identity
from aip_identity.integrations.langchain_tools import get_aip_tools

# === Setup: Each agent gets its own AIP identity ===

# In production, each agent would have its own credentials file
researcher_client = ensure_identity(
    "crewai-researcher",
    platform="crewai",
    credentials_path="/tmp/aip_researcher.json",
)

writer_client = ensure_identity(
    "crewai-writer",
    platform="crewai",
    credentials_path="/tmp/aip_writer.json",
)

print(f"Researcher: {researcher_client.did}")
print(f"Writer:     {writer_client.did}")

# === Demo: Signed output exchange ===

# Researcher signs their findings
research_output = "Market analysis shows 40% growth in AI agent adoption Q4 2025."
signature = researcher_client.sign(research_output.encode()).hex()

print(f"\nResearcher signed output:")
print(f"  Content: {research_output}")
print(f"  Signature: {signature[:40]}...")

# Writer verifies the research came from the researcher
from nacl.signing import VerifyKey
import base64

verify_key = VerifyKey(base64.b64decode(researcher_client.public_key))
try:
    verify_key.verify(research_output.encode(), bytes.fromhex(signature))
    print(f"\n✓ Writer verified: output is authentically from {researcher_client.did}")
except Exception:
    print(f"\n✗ Verification failed — output may be tampered")

# === CrewAI Integration Pattern ===
print("""
# === Full CrewAI Integration ===
#
# from crewai import Agent, Task, Crew
# from aip_identity.integrations.langchain_tools import get_aip_tools
#
# researcher = Agent(
#     role="Senior Researcher",
#     goal="Find and verify information",
#     tools=get_aip_tools(),  # AIP tools work natively with CrewAI
#     backstory="Expert researcher with cryptographic identity"
# )
#
# writer = Agent(
#     role="Content Writer",
#     goal="Create verified content",
#     tools=get_aip_tools(),
#     backstory="Writer who signs all outputs for accountability"
# )
#
# research_task = Task(
#     description="Research AI agent trends. Sign your findings.",
#     agent=researcher,
# )
#
# writing_task = Task(
#     description="Write a report. Verify the research signature first.",
#     agent=writer,
# )
#
# crew = Crew(agents=[researcher, writer], tasks=[research_task, writing_task])
# result = crew.kickoff()
""")

print("✓ CrewAI integration ready")
print(f"  Researcher DID: {researcher_client.did}")
print(f"  Writer DID: {writer_client.did}")
print(f"  AIP tools: {len(get_aip_tools())} available")
