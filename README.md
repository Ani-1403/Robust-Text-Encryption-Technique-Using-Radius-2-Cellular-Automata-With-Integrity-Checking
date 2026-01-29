# Robust Text Encryption Using Radius-2 Cellular Automata

> A novel symmetric-key block cipher integrating Hyper-Chaotic Systems and 16-step Reversible Cellular Automata for high-entropy data security.

## Project Overview
[cite_start]This project introduces a cryptographic primitive that combines **Chaos Theory** with **Cellular Automata (CA)** to address the limitations of standard encryption models[cite: 85]. [cite_start]Unlike traditional CA ciphers restricted to a 3-bit neighborhood (256 rules), this algorithm employs a **5-bit neighborhood (Radius 2)**, expanding the rule space to **$2^{32}$ (approx. 4.29 billion) configurations**[cite: 86, 103].

[cite_start]The system features a custom **Cipher Block Chaining (CBC)** mode that utilizes "Residual Data"—a secondary byproduct of the CA operation—to provide a built-in integrity verification mechanism, detecting chain corruption without external hash functions[cite: 88, 111].



---

## Key Features

* [cite_start]**5-Bit Neighborhood Architecture:** Utilizes a radius-2 ($i-2$ to $i+2$) neighborhood coupled with a selector bit, creating a non-linear transformation map far more complex than elementary CA[cite: 111].
* [cite_start]**Hyper-Chaotic Key Scheduling:** Implements the **Logistic Map** to dynamically generate 16 unique sub-keys from a 512-bit master key, ensuring a strong Avalanche Effect[cite: 87, 105].
* [cite_start]**Dynamic Rule Generation:** Encryption rules change deterministically 16 times per block, rendering brute-force rule analysis computationally infeasible[cite: 111].
* [cite_start]**Integrated Integrity Check:** A dual-output mechanism (Ciphertext + Residual Data) allows for decryption verification that instantly flags data tampering[cite: 111].
* [cite_start]**Statistical Randomness:** Achieves a Pearson Correlation Coefficient near **0.0**, consistently outperforming DES and matching AES-256[cite: 89].

---

## System Architecture

[cite_start]The cipher operates on **64-bit data blocks** through a 3-stage pipeline[cite: 238]:

1.  **Key Generation Module:**
    * Input: User Passphrase.
    * [cite_start]Process: Hashed via **SHA-512** to create a Master Key, then expanded using the **Chaotic Logistic Map** [cite: 243-244].
    * [cite_start]Output: 16 unique 32-bit rules[cite: 239].

2.  **Encryption Engine (Core):**
    * [cite_start]Uses a **16-step reversible CA network**[cite: 101].
    * [cite_start]Transforms two 64-bit rows (Upper and Lower) based on dynamic rules derived from the key[cite: 257].

3.  **CBC Mode & Integrity:**
    * [cite_start]Implements "Residual Chaining" where the residual output of block $N-1$ serves as the input context for block $N$[cite: 258].



---

## 📊 Comparative Analysis

[cite_start]The proposed solution fills the gap between lightweight ciphers and heavy standard algorithms[cite: 160].

| Feature | DES | AES | Standard 3-Bit CA | **Proposed 5-Bit CA** |
| :--- | :--- | :--- | :--- | :--- |
| **Key Size** | 56-bit | 128/256-bit | Variable | **512-bit (derived)** |
| **Block Size** | 64-bit | 128-bit | Variable | **64-bit** |
| **Rule/S-Box** | Static | Static | Static (256 rules) | **Dynamic ($2^{32}$ rules)** |
| **Integrity** | None | None | None | **Built-in Chain Check** |

---

## Performance & Results

The cipher was benchmarked using the **Pearson Correlation Coefficient** to measure the linear relationship between plaintext and ciphertext. A value closer to **0** indicates higher security (less pattern leakage).

* [cite_start]**Custom 16-Step CA:** ~0.002 (Near Zero Correlation)[cite: 484, 489].
* [cite_start]**DES (Standard):** ~0.08 (Higher correlation, less random)[cite: 485].
* [cite_start]**AES-256:** ~0.03 (Standard security baseline)[cite: 488].



---
