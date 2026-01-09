# 🛡️ MCP Sentinel: Runtime Security Gateway for Agentic AI

> **Your AI Agent is basically a Junior Developer with root access. Sentinel is the Supervisor.**

## 🚨 The Problem

We are entering the era of **Agentic AI**. Large Language Models (LLMs) are no longer just chatbox text generators; via the **Model Context Protocol (MCP)**, they now have "hands"—access to databases, APIs, file systems, and Slack channels.

Current security tools (LLM Firewalls, WAFs) focus on **Text & Semantics** (PII masking, toxicity, prompt injection).
They fail to address **Execution Logic**:

* What if an Agent enters an infinite loop calling a paid API?
* What if an Agent executes `SELECT *` on a production DB without a `LIMIT` clause?
* What if an Agent tries to pipe sensitive company data to a public domain?

**Standard firewalls see valid SQL syntax. Sentinel sees a Data Exfiltration attempt.**

## ⚡ The Solution

**MCP Sentinel** is a Man-in-the-Middle security layer that sits between your LLM Client (e.g., Claude Desktop, LangChain) and your MCP Servers (Tools).

It intercepts JSON-RPC messages in real-time to enforce **State & Logic Policies**.

### Key Features (MVP)
- ✅ **Deep Inspection:** Analyzes tool arguments, not just prompt text.
- 🛡️ **Exfiltration Guard:** Detects and blocks unbounded queries (e.g., missing `LIMIT` in SQL).
- 🛑 **Circuit Breaker:** (Roadmap) Stops infinite loops and excessive tool usage.
- 🚦 **Human-in-the-Loop:** (Roadmap) Pauses execution for critical actions (DELETE/DROP) requiring approval.

## 📸 Proof of Concept

*Sentinel blocking a simulated Data Exfiltration attempt where an Agent tried to dump a database without limits.*

![Sentinel Demo](demo.png)

## 🛠️ Quick Start (Interceptor Mode)

Sentinel works by piping standard input/output, acting as a transparent proxy for the MCP protocol.

```bash
# Simulating an attack via pipeline
cat attack.json | python gateway.py