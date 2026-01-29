import os
# Import from the v2 core file
from ca_core_16step_5bit_v2 import (
    BLOCK_SIZE,
    unpad,
    print_divider,
    as_hex,
    generate_all_keys_and_rules_verbose,
    apply_ca_step
)

def main():
    print_divider("START: 16-STEP DECRYPTION PROGRAM (CBC MODE)")
    
    # --- PHASE 1: KEY & RULE GENERATION ---
    print_divider("PHASE 1: KEY & RULE GENERATION")
    
    key_input = input("Enter the *exact same secret key* (passphrase) used for encryption:\n> ")
    if not key_input:
        print("Error: Key is required for decryption.")
        return
        
    all_rules = generate_all_keys_and_rules_verbose(key_input) # List of 16 (f,b) tuples
    
    # --- GET ENCRYPTED DATA ---
    print_divider("PHASE 2: INPUT ENCRYPTED DATA")

    input_filename = "encryption_data.txt"
    row_0_constant_expected = 0
    
    try:
        if os.path.exists(input_filename):
            print(f"✓ Found '{input_filename}'. Loading data from file...")
            with open(input_filename, "r") as f:
                row_0_hex = f.readline().strip()
                ct_hex_str = f.readline().strip()
                fr_hex_str = f.readline().strip()
            
            if not row_0_hex or not ct_hex_str or not fr_hex_str:
                raise ValueError("File is incomplete.")
                
            row_0_constant_expected = int(row_0_hex, 16)
            print("  ✓ Data loaded successfully.")

        else:
            print(f"✗ File '{input_filename}' not found.")
            raise FileNotFoundError

    except Exception as e:
        print(f"  ! Could not read from file ({e}). Please paste data manually.")
        row_0_hex = input("Enter the Row 0 Constant (First Random Data) (hex):\n> ").strip()
        ct_hex_str = input("Enter the full hex Ciphertext (Row 32):\n> ").strip()
        fr_hex_str = input("Enter the full hex Final Residual Data (Row 33):\n> ").strip()
        
        try:
            row_0_constant_expected = int(row_0_hex, 16)
        except ValueError:
            print("\nError: Invalid hex for Row 0. Exiting.")
            return

    try:
        ct_bytes = bytes.fromhex(ct_hex_str)
        fr_bytes = bytes.fromhex(fr_hex_str)
    except ValueError:
        print("\nError: Invalid hex string. Exiting.")
        return

    if len(ct_bytes) != len(fr_bytes) or len(ct_bytes) % BLOCK_SIZE != 0:
        print("\nError: Data lengths are invalid or don't match. Exiting.")
        return

    # --- PHASE 4: DECRYPTION (PER-BLOCK) ---
    print_divider("PHASE 4: 16-STEP DECRYPTION (CBC MODE)")
    
    all_plaintext_bytes = b''
    block_count = 0
    
    # --- MODIFICATION: Setup for the new summary table ---
    previous_residual_expected_int = row_0_constant_expected
    all_checks_passed = True
    chain_check_results = [] # Store (expected, recovered) tuples for the table
    
    for i in range(0, len(ct_bytes), BLOCK_SIZE):
        block_count += 1
        print(f"\n--- Processing Block {block_count} ---")
        
        rows = {}
        
        current_ct_bytes = ct_bytes[i : i + BLOCK_SIZE]
        current_fr_bytes = fr_bytes[i : i + BLOCK_SIZE]
        
        current_ct_int = int.from_bytes(current_ct_bytes, 'big')
        current_fr_int = int.from_bytes(current_fr_bytes, 'big')
        
        rows[32] = current_ct_int
        rows[33] = current_fr_int
        
        print(f"  Input CT (Row 32): {as_hex(rows[32])}")
        print(f"  Input FR (Row 33): {as_hex(rows[33])}")
        
        # --- 16-STEP ASYMMETRIC DECRYPTION CHAIN ---
        for step in range(15, 0, -1): # step = 15, 14, ..., 1
            print(f"\n  Decryption Step (reversing Enc Step {step + 1}, using Rule Set {step})...")
            
            f_rule, b_rule = all_rules[step]
            rule_set_name = f"Rule Set {step}"
            
            idx_U_in = step * 2 + 3
            idx_L_in = step * 2 + 2
            idx_U_out = step * 2 + 1
            idx_L_out = step * 2
            
            step_name_1 = f"Row {idx_U_out:02d} (Rec)"
            rows[idx_U_out] = apply_ca_step(rows[idx_U_in], rows[idx_L_in], f_rule, b_rule, step_name_1, rule_set_name)
            
            step_name_2 = f"Row {idx_L_out:02d} (Rec)"
            rows[idx_L_out] = apply_ca_step(rows[idx_L_in], rows[idx_U_out], f_rule, b_rule, step_name_2, rule_set_name)

        # Final Decryption Step (using Rule Set 0)
        print(f"\n  Final Decryption Step (reversing Enc Step 1, using Rule Set 0)...")
        f_rule, b_rule = all_rules[0]
        
        step_name_final = "Row 01 (Rec. Plaintext)"
        row_1_rec = apply_ca_step(rows[3], rows[2], f_rule, b_rule, step_name_final, "Rule Set 0")
        
        print("  Recovering Row 00 for chain test...")
        step_name_corr = "Row 00 (Rec. Chain Input)"
        row_0_rec = apply_ca_step(rows[2], row_1_rec, f_rule, b_rule, step_name_corr, "Rule Set 0")

        all_plaintext_bytes += row_1_rec.to_bytes(BLOCK_SIZE, 'big', signed=False)
        
        # --- CHAIN INTEGRITY CHECK (for this block) ---
        print("\n  --- CHAIN INTEGRITY CHECK ---")
        if row_0_rec == previous_residual_expected_int:
            print(f"  ✓ SUCCESS: Recovered Row 0 matches expected chain value.")
            print(f"    > Expected:  {as_hex(previous_residual_expected_int)}")
            print(f"    > Recovered: {as_hex(row_0_rec)}")
        else:
            print(f"  ✗ FAILED: Recovered Row 0 does NOT match expected chain value!")
            print(f"    > Expected:  {as_hex(previous_residual_expected_int)}")
            print(f"    > Recovered: {as_hex(row_0_rec)}")
            all_checks_passed = False
        
        # --- MODIFICATION: Store results for the final table ---
        chain_check_results.append((previous_residual_expected_int, row_0_rec))
        
        # Update the expected value for the *next* block
        previous_residual_expected_int = current_fr_int


    # --- PHASE 6: FINALIZATION ---
    print_divider("PHASE 6: FINALIZATION")
    print(f"Successfully decrypted {block_count} blocks.")
    print(f"  Raw decrypted (padded) hex: {all_plaintext_bytes.hex()}")

    try:
        unpadded_data = unpad(all_plaintext_bytes, BLOCK_SIZE)
        print(f"  Unpadded data (hex): {unpadded_data.hex()}")
        
        print("\n  Decoding from UTF-8...")
        final_message = unpadded_data.decode('utf-8')
        
        print_divider("DECRYPTION COMPLETE")
        print("Recovered Message:")
        print(final_message)
        
    except UnicodeDecodeError:
        print_divider("DECRYPTION COMPLETE (WITH WARNING)")
        print("Could not decode as UTF-8 text.")
        print("This is normal if the original was not text.")
        print(f"  Final unpadded hex: {unpadded_data.hex()}")
    except ValueError as e:
        print_divider("DECRYPTION FAILED")
        print(f"!! ERROR: {e}")
        if not all_checks_passed:
            print("!! This was caused by a FAILED CHAIN INTEGRITY CHECK.")
            print("!! This *always* means the KEY was WRONG or the")
            print("!! encrypted data was corrupted or entered incorrectly.")
        else:
            print("!! This was likely caused by invalid padding (wrong key?).")
    
    # --- MODIFICATION: Final summary table ---
    print_divider("ROW 0 CHAIN TEST SUMMARY")
    
    print("\n  --- Detailed Chain Verification Table ---")
    print("  Block | Status   | Expected Value     | Recovered Value")
    print("  ------|----------|--------------------|--------------------")
    
    for i, (expected, recovered) in enumerate(chain_check_results):
        block_num = i + 1
        # Use as_hex to format as 0x...
        expected_hex = as_hex(expected)
        recovered_hex = as_hex(recovered)
        
        status = "✓ MATCH" if expected == recovered else "✗ FAILED"
        
        # Use f-string formatting to align the columns
        print(f"  {block_num:<5} | {status:<8} | {expected_hex:18} | {recovered_hex:18}")

    print("\n  --- Final Summary ---")
    if all_checks_passed:
        print(f"✓ SUCCESS: All {block_count} blocks were correctly chained and verified.")
    else:
        print(f"✗ FAILED: One or more blocks failed the chain integrity check.")
        print("! This *always* means the KEY was WRONG or the data was corrupted.")


if __name__ == "__main__":
    main()