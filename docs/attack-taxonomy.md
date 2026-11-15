# AgentNet — Attack Taxonomy

## 1. Introduction

This document defines the attack categories considered in the AgentNet project.

The taxonomy provides a consistent classification system for generating, labeling, and evaluating benign and malicious network sessions involving MCP and A2A agent communication.

## 2. Traffic Classification

AgentNet divides network sessions into two primary classes:

| Class | Description | Label |
|---|---|---|
| Benign | Normal and authorized agent communication | 0 |
| Attack | Communication associated with a controlled attack scenario | 1 |

Each attack session also receives a specific attack-category label.

## 3. Attack Categories

### AT-01: Tool Poisoning

**Description:** Manipulation of tool descriptions or metadata to influence an agent into selecting or using a tool in an unintended way.

**Target:** MCP tool discovery and descriptions.

**Detection Indicators:** Unusual tool descriptions, suspicious metadata, and unexpected tool-selection patterns.

### AT-02: Tool Rug Pull

**Description:** A previously trusted tool changes its behavior after initial discovery or approval.

**Target:** MCP tool behavior and tool responses.

**Detection Indicators:** Changes in tool behavior, unexpected response patterns, and differences between previously observed and current tool behavior.

### AT-03: Prompt Injection Through Tool Output

**Description:** Untrusted content returned by a tool attempts to influence an agent's subsequent behavior.

**Target:** Tool responses and agent interactions.

**Detection Indicators:** Suspicious response patterns and unusual follow-up requests or actions.

### AT-04: Confused Deputy

**Description:** An agent is manipulated into using its legitimate permissions to perform an action that the requesting party is not authorized to perform.

**Target:** Agent permissions and tool invocation.

**Detection Indicators:** Unexpected tool usage, unusual request sequences, and actions inconsistent with the authorized interaction context.

### AT-05: Data Exfiltration

**Description:** Sensitive information is transferred to an unauthorized destination through agent communication.

**Target:** Agent data exchange and network communication.

**Detection Indicators:** Unusual outbound traffic, unexpected destinations, and abnormal data-transfer patterns.

### AT-06: Agent-Card Spoofing

**Description:** An unauthorized agent presents misleading identity or capability information to appear as a legitimate A2A agent.

**Target:** A2A agent identity and discovery information.

**Detection Indicators:** Inconsistent agent identity information, unexpected capability changes, and suspicious agent-card metadata.

### AT-07: Unauthorized Physical Actuation

**Description:** An agent attempts to trigger a physical device operation without the required authorization.

**Target:** MCP-connected hardware and device-control interfaces.

**Detection Indicators:** Unexpected device-control requests and operations inconsistent with the testbed's authorization rules.

## 4. Dataset Label Structure

Every captured session should contain the following information:

| Field | Description |
|---|---|
| session_id | Unique session identifier |
| traffic_class | Benign or Attack |
| class_label | 0 for benign, 1 for attack |
| attack_id | AT-01 to AT-07; empty for benign |
| attack_name | Attack category name |
| protocol | MCP or A2A |
| transport | HTTP or HTTPS/TLS |
| environment | Software or Hardware |
| outcome | Success or Failure |
| capture_file | Associated packet-capture file |

## 5. Attack Outcome Classification

Attack sessions must also record their outcome:

- **Success:** The predefined test scenario's success condition was met.
- **Failure:** The scenario was attempted, but its success condition was not met.

An attack attempt must not automatically be labeled successful. Outcomes should be validated using the testbed's predefined conditions, such as application logs or device-state records.

## 6. Dataset Labeling Rules

1. Every session must have a unique session ID.
2. Normal authorized communication must be labeled Benign.
3. Sessions associated with an attack scenario must be labeled Attack.
4. Every attack session must have an attack category.
5. Attack success and failure must be recorded separately.
6. Missing or ambiguous labels must be reviewed rather than guessed.
7. The same labeling rules must be applied to plaintext and TLS traffic.
8. Training, validation, and testing splits must avoid unintended session leakage.

## 7. Scope

The taxonomy covers seven attack categories defined in the AgentNet proposal.

It is intended for controlled dataset generation and defensive intrusion-detection research. It does not represent an exhaustive list of all possible threats against MCP and A2A systems.