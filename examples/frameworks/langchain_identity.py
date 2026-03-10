#!/usr/bin/env python3
"""
LangChain + AIP Identity Example

Demonstrates a LangChain agent that can:
- Identify itself cryptographically
- Verify other agents
- Sign messages to prove authorship
- Check trust scores before acting on information

Requirements:
    pip install aip-identity langchain-core langchain-openai

Usage:
    python langchain_identity.py
"""

import json
import os

# === Step 1: Ensure AIP identity exists ===
# This is the magic line — loads existing credentials or registers a new agent
from aip_identity.integrations.auto import ensure_identity

client = ensure_identity("langchain-research-agent", platform="langchain")
print(f"Agent identity: {client.did}")

# === Step 2: Get LangChain-compatible tools ===
from aip_identity.integrations.langchain_tools import get_aip_tools

aip_tools = get_aip_tools()
print(f"Loaded {len(aip_tools)} AIP tools: {[t.name for t in aip_tools]}")

# === Step 3: Use tools directly (no LLM needed for demo) ===

# Who am I?
whoami = aip_tools[0]  # aip_whoami
identity = json.loads(whoami.invoke({}))
print(f"\nMy identity:")
print(f"  DID: {identity['did']}")
print(f"  Public key: {identity['public_key'][:20]}...")

# Sign a message
sign_tool = aip_tools[5]  # aip_sign_message
signed = json.loads(sign_tool.invoke({"message": "This research finding is verified by me."}))
print(f"\nSigned message:")
print(f"  Message: {signed['message']}")
print(f"  Signature: {signed['signature'][:40]}...")

# === Step 4: Integration with a LangChain agent (conceptual) ===
print("""
# === Full LangChain Agent Integration ===
#
# from langchain_openai import ChatOpenAI
# from langchain.agents import create_tool_calling_agent, AgentExecutor
# from langchain_core.prompts import ChatPromptTemplate
# from aip_identity.integrations.langchain_tools import get_aip_tools
#
# llm = ChatOpenAI(model="gpt-4o")
# tools = get_aip_tools() + your_other_tools
#
# prompt = ChatPromptTemplate.from_messages([
#     ("system", "You are a research agent with a cryptographic identity. "
#                "Use AIP tools to verify sources and sign your outputs."),
#     ("human", "{input}"),
#     ("placeholder", "{agent_scratchpad}"),
# ])
#
# agent = create_tool_calling_agent(llm, tools, prompt)
# executor = AgentExecutor(agent=agent, tools=tools)
#
# result = executor.invoke({
#     "input": "Who am I? Sign a summary of your findings."
# })
""")

print("✓ LangChain integration ready")
print(f"  Agent DID: {client.did}")
print(f"  Credentials: ~/.aip/credentials.json")
print(f"  Tools available: {len(aip_tools)}")
