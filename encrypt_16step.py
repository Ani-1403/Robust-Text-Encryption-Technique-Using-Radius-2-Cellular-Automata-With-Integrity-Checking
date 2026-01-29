import os
# Import from the v2 core file
from ca_core_16step_5bit_v2 import (
    BLOCK_SIZE,
    pad,
    print_divider,
    as_hex,
    generate_all_keys_and_rules_verbose,
    generate_random_data_verbose,
    apply_ca_step
)

def main():
    print_divider("START: 16-STEP ENCRYPTION PROGRAM (CBC MODE)")
    
    # --- PHASE 1: KEY & RULE GENERATION ---
    print_divider("PHASE 1: KEY & RULE GENERATION")
    
    key_input = input("Enter your secret key (passphrase):\n> ")
    if not key_input:
        print("Error: Key is required.")
        return
    
    all_rules = generate_all_keys_and_rules_verbose(key_input) # List of 16 (f,b) tuples

    # --- PHASE 2: PRE-PROCESSING ---
    print_divider("PHASE 2: PRE-PROCESSING")
    pt_string = input("\nEnter the full plaintext message to encrypt:\n> ")
    if not pt_string:
        pt_string = "This is a test."
        print(f"[Using default message: '{pt_string}']")
    
    pt_bytes = pt_string.encode('utf-8')
    
    # Step 6: Generate Row 0 (from *entire* message)
    # This is our "first random data", or Initialization Vector (IV)
    row_0_constant = generate_random_data_verbose(pt_bytes)
    
    # Step 7: Pad and Block
    print("\n  Padding and Blocking...")
    padded_data = pad(pt_bytes, BLOCK_SIZE)
    print(f"  Original length: {len(pt_bytes)} bytes")
    print(f"  Padded length:   {len(padded_data)} bytes (to {BLOCK_SIZE}-byte blocks)")
    print(f"  Padded data (hex): {padded_data.hex()}")
    
    # --- PHASE 3: ENCRYPTION (PER-BLOCK) ---
    print_divider("PHASE 3: 16-STEP ENCRYPTION (CBC MODE)")
    
    all_ciphertext_bytes = b''
    all_residual_bytes = b''
    block_count = 0
    
    # --- MODIFICATION: Initialize the CBC chain ---
    # The first block's "random data" is the row_0_constant
    previous_residual_int = row_0_constant
    
    for i in range(0, len(padded_data), BLOCK_SIZE):
        block_count += 1
        print(f"\n--- Processing Block {block_count} ---")
        
        rows = [] 
        
        # Step 8: Set Initial Inputs
        current_block_bytes = padded_data[i : i + BLOCK_SIZE]
        
        # --- MODIFICATION: Use the residual from the *previous* block ---
        # For Block 1, this is row_0_constant.
        # For Block 2, this is the residual from Block 1.
        rows.append(previous_residual_int) # rows[0]
        rows.append(int.from_bytes(current_block_bytes, 'big')) # rows[1]
        
        print(f"  Row 00 (Chain Input):{as_hex(rows[0])}")
        print(f"  Row 01 (Plaintext):  {as_hex(rows[1])}  (bytes: {current_block_bytes})")
        
        # --- 16-STEP ASYMMETRIC CHAIN ---
        for step in range(16):
            print(f"\n  Encryption Step {step + 1} (using Rule Set {step})...")
            
            f_rule, b_rule = all_rules[step]
            rule_set_name = f"Rule Set {step}"
            
            idx_U1 = step * 2       # 0, 2, 4, ... 30
            idx_L1 = step * 2 + 1   # 1, 3, 5, ... 31
            
            step_name_1 = f"Row {step * 2 + 2:02d} (Int/CTx)"
            row_A = apply_ca_step(rows[idx_U1], rows[idx_L1], f_rule, b_rule, step_name_1, rule_set_name)
            rows.append(row_A) # e.g., rows[2]
            
            step_name_2 = f"Row {step * 2 + 3:02d} (Res/FRx)"
            row_B = apply_ca_step(rows[idx_L1], row_A, f_rule, b_rule, step_name_2, rule_set_name)
            rows.append(row_B) # e.g., rows[3]
        
        final_ciphertext = rows[32]
        final_residual = rows[33]
        
        # --- MODIFICATION: Update the chain for the *next* block ---
        previous_residual_int = final_residual
        
        all_ciphertext_bytes += final_ciphertext.to_bytes(BLOCK_SIZE, 'big', signed=False)
        all_residual_bytes += final_residual.to_bytes(BLOCK_SIZE, 'big', signed=False)

    # --- FINAL OUTPUT ---
    print_divider("ENCRYPTION COMPLETE")
    print(f"Successfully encrypted {block_count} blocks.")
    
    # Convert to hex strings for output
    row_0_hex = as_hex(row_0_constant)[2:] # Remove '0x' prefix
    ct_hex = all_ciphertext_bytes.hex()
    fr_hex = all_residual_bytes.hex()

    print("\n1. Row 0 Constant (First Random Data) (hex):")
    print(row_0_hex)

    print("\n2. Ciphertext (Row 32) (hex):")
    print(ct_hex)
    
    print("\n3. Final Residual Data (Row 33) (hex):")
    print(fr_hex)

    # Save all data to a file
    try:
        output_filename = "encryption_data.txt"
        with open(output_filename, "w") as f:
            f.write(f"{row_0_hex}\n") # Line 1: Row 0 (IV)
            f.write(f"{ct_hex}\n")    # Line 2: Ciphertext
            f.write(f"{fr_hex}\n")    # Line 3: Residuals
        print(f"\n✓ Encryption data saved to '{output_filename}'")
    except Exception as e:
        print(f"\n✗ Error saving encryption data to file: {e}")


if __name__ == "__main__":
    main()