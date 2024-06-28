# Parasyte Project Architecture

## Introduction

The Parasyte project simulates the behavior of worm malware to facilitate research and education on cybersecurity threats and defenses. This document outlines the high-level architecture of the project, describing the key components and their interactions.

## System Overview

Parasyte is designed to be modular, with distinct components handling different aspects of the worm simulation, including network scanning, vulnerability exploitation, payload delivery, and execution. The project is developed in C++ for core functionalities, with scripts in PowerShell and Bash for simulating payload activities in a controlled environment.

## Component Architecture

### Main Components

1. **NetScanner**
- Responsible for scanning the virtual network to identify potential targets. It simulates the initial reconnaissance phase of a worm's lifecycle.
- Performs IP sweeping and port scanning.
- Detects services running on open ports and attempts to identify known vulnerabilities.

2. **Exploit Module**
- Simulates various exploitation techniques to gain unauthorized access to target systems. It is designed to be extensible, allowing for the addition of new exploits over time.
- Houses a collection of exploit techniques, each tailored to specific vulnerabilities.
- Capable of being extended to include new exploits as they are discovered.

3. **Payload Module**:
- Represents the malicious code or action that is executed on the target system post-exploitation.
- Contains various payload examples, from data exfiltration scripts to benign activities for demonstration.
- Demonstrates how payloads can be dynamically selected and executed based on the target system's characteristics.

4. **Parasyte Controller**
- Acts as the central management unit for coordinating the activities of the malware simulation.
- Initiates the network scanning process and identifies targets.
- Selects and executes exploits based on identified vulnerabilities.
- Manages payload delivery and execution on successfully exploited targets.

5. **Logging and Analysis**
- Records actions taken during the simulation for post-operation analysis and learning.
- Captures detailed logs of the scanning, exploitation, and payload delivery processes.
- Facilitates the review of simulation steps and outcomes.

## Interactions

- Initialization: The Controller begins the simulation by initiating the Network Scanner to identify potential targets.
- Target Identification: Upon identifying potential targets, the Controller queries the Exploit Module to select appropriate exploits based on the vulnerabilities discovered by the Network Scanner.
- Exploitation: The selected exploits are executed against their respective targets. Success or failure is logged.
- Payload Delivery: For each successfully exploited target, the Controller directs the delivery and execution of a Payload.
- Logging: Throughout the process, all actions and their outcomes are logged by the Logging and Analysis component for later review.

## Modular Design

The modular design allows for each component of the Parasyte project to be developed, tested, and improved independently. This also facilitates the easy addition of new exploits, payloads, and functionality as the project grows.

## Extension Points

- Exploit Module: New exploits can be added as subclasses of a general Exploit class.
- Payload: New payload types can be integrated by implementing a Payload interface.
- Network Scanner: Additional scanning techniques and vulnerability assessments can be incorporated into the scanning process.