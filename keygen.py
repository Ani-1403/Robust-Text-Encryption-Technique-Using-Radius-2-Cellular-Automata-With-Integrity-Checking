import hashlib

# Try to import the necessary functions from your core CA file
try:
    from ca_core_16step_5bit_v2 import (
        print_divider,
        generate_ca_rule_verbose 
    )
except ImportError:
    print("="*70)
    print("FATAL ERROR: Could not find 'ca_core_16step_5bit_v2.py'.")
    print("Please make sure 'key_rule_analyzer.py' is in the same")
    print("directory as 'ca_core_16step_5bit_v2.py'.")
    print("="*70)
    exit()

def main():
    """
    Runs a series of tests to demonstrate the avalanche effect.
    A minimal change in the input passphrase should result in
    a completely different 64-byte key and, consequently,
    a completely different 32-bit rule set.
    """
    print_divider("Key & Rule Generation Avalanche Test")
    print("This script demonstrates how a tiny change in the input passphrase")
    print("creates a completely different 64-byte key (SHA-512) and,")
    print("consequently, a completely different 32-bit rule set.\n")

    # --- 5 Test Cases with slight variations ---
    test_cases = [
        ("Case 1: Base Passphrase", "my_secret_key"),
        ("Case 2: One-char change (Y)", "my_secret_keY"), # Uppercase 'Y'
        ("Case 3: One-char added (.)", "my_secret_key."),  # Added period
        ("Case 4: One-char added (space)", "my_secret_key "), # Added space
        ("Case 5: Different Passphrase", "another_key_123") # Totally different
    ]
    
    results = [] # To store (name, f_rule, b_rule) for the final summary

    # --- Run Each Test Case ---
    for case_name, passphrase in test_cases:
        # This function prints its own divider
        
        # 1. Generate the 64-byte "Key 0" from the passphrase
        # This simulates the first step of generate_all_keys_and_rules
        print(f"  Input Passphrase: '{passphrase}'\n")
        key_0 = hashlib.sha512(passphrase.encode()).digest()
        
        # 2. Call the verbose rule generator from the core file.
        #    This will print all the details:
        #    - The full 64-byte Key 0
        #    - The 4-byte XOR-folding process
        #    - The final Forward and Backward rules (in decimal)
        #    - The 5-bit truth tables
        f_rule, b_rule = generate_ca_rule_verbose(key_0, case_name)
        
        # 3. Store the result for the summary table
        results.append((case_name, f_rule, b_rule))
        print(f"\n{'-'*70}\n")


    # --- Final Summary Table ---
    print_divider("Final Summary of Rule Variation")
    print("Note how even a 1-bit change in the passphrase (like 'y' vs 'Y')")
    print("results in completely different rules (the avalanche effect).\n")
    
    print("  Case                       | Forward Rule (Decimal) | Backward Rule (Decimal)")
    print("  ---------------------------|------------------------|-------------------------")
    
    for name, f_rule, b_rule in results:
        # Format the strings to align in a table
        print(f"  {name:<26} | {f_rule:<22} | {b_rule:<23}")

if __name__ == "__main__":
    main()