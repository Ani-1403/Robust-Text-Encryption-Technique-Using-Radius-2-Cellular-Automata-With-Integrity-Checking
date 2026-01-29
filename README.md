# Robust Text Encryption Using Radius-2 Cellular Automata

> **A novel symmetric-key block cipher integrating Hyper-Chaotic Systems and 16-step Reversible Cellular Automata for high-entropy data security.**

## Project Overview
[cite_start]The development of robust encryption systems is crucial to data security in the face of escalating cyber threats[cite: 84]. [cite_start]This project introduces a novel symmetric-key block cipher based on **Cellular Automata (CA)** and **Chaos Theory**[cite: 85]. [cite_start]Unlike standard elementary CA which are restricted to 256 rules, this proposed algorithm employs a **16-step reversible CA with a 5-bit neighborhood**, significantly expanding the rule space to **$2^{32}$ configurations**[cite: 86].

[cite_start]The system includes a custom **Cipher Block Chaining (CBC)** mode utilizing "Residual Data" to provide a built-in integrity verification mechanism[cite: 88].

![System Architecture](https://via.placeholder.com/800x400?text=System+Architecture+Placeholder)
*(Note: Replace the placeholder above with "Figure 4.1: Working of the proposed solution" from page 16 of your report)*

---

## Key Features

* [cite_start]**Expanded Rule Space**: By using a 5-bit neighborhood, the rule space is expanded to approximately 4.29 billion ($2^{32}$) unique rules, far exceeding the 256 rules of standard CA[cite: 86].
* [cite_start]**Hyper-Chaotic Key Scheduling**: Dynamic key scheduling is achieved using the **Logistic Map**, a chaotic function that ensures a strong Avalanche Effect[cite: 87].
* [cite_start]**Built-in Integrity**: A custom CBC mode uses "Residual Data" (a byproduct of encryption) to verify data integrity without needing a separate hash function[cite: 88, 111].
* [cite_start]**Dynamic Rules**: The encryption rules change deterministically 16 times per block, ensuring high non-linearity[cite: 111].

---

## System Architecture

[cite_start]The system operates in three main stages[cite: 238]:

1.  [cite_start]**Key Generation**: Converts the user passphrase into a 512-bit Master Key via SHA-512, then uses a Chaotic Logistic Map to derive 16 unique 32-bit rules[cite: 243, 244].
2.  **Encryption Engine**: A 16-step 5-bit CA core transforms the plaintext. [cite_start]The "Upper Row" bit selects whether to apply a Forward or Backward rule to the "Lower Row" neighborhood[cite: 271].
3.  **Decryption & Verification**: The process is reversed. [cite_start]If the recovered "Row 0" does not match the residual from the previous block, the system flags a "Chain Integrity Failed" error[cite: 395, 397].

---

## Performance & Analysis

The cipher was tested using the **Pearson Correlation Coefficient** to measure randomness (a value closer to 0 is better).

| Algorithm | Correlation Coefficient | Performance |
| :--- | :--- | :--- |
| **Custom 16-Step CA** | **~0.002** | [cite_start]**Near-zero correlation (Best)** [cite: 89] |
| AES-256 | ~0.03 | [cite_start]Standard statistical randomness [cite: 89] |
| DES | ~0.08 | [cite_start]Consistently outperformed by Custom CA [cite: 89] |

> [cite_start]"This work validates the potential of combining hyper-chaotic systems with complex CA architectures to create secure, high-entropy cryptographic primitives." [cite: 90]

---
