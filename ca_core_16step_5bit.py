import hashlib
import os
from decimal import Decimal, getcontext

BLOCK_SIZE = 8 # 64 bits = 8 bytes

# --- 1. PADDING (Standard) ---

def pad(data, block_size):
    """Pads data to a multiple of block_size using PKCS#7."""
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def unpad(data, block_size):
    """Removes PKCS#7 padding from data."""
    if not data:
        raise ValueError("Cannot unpad empty data")
    
    padding_len = data[-1]
    
    if padding_len > block_size or padding_len == 0:
        raise ValueError("Invalid padding length")
    
    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid padding bytes")
        
    return data[:-padding_len]

# --- 2. VERBOSE HELPER FUNCTIONS ---

def print_divider(title):
    """Prints a clean, formatted divider title."""
    print(f"\n{'='*25} {title.upper()} {'='*25}")

def as_hex(value_int):
    """Helper to format a 64-bit integer as a 16-char hex string."""
    return f"0x{value_int:016x}"

# --- MODIFIED: 5-BIT TRUTH TABLE (32-BIT RULE) ---
def print_truth_table_5bit(rule_num):
    """
    Prints the 32-bit truth table for a 5-bit CA rule.
    '11111' -> bit 31, ..., '00000' -> bit 0
    """
    # Rule is 32 bits long
    rule_str = bin(rule_num)[2:].zfill(32) 
    print("    Neighborhood  | Output")
    print("    --------------|--------")
    
    # Iterate 31 down to 0 (32 states)
    for j in range(31, -1, -1): 
        # Neighborhood is 5 bits long
        neighborhood = bin(j)[2:].zfill(5)
        # '11111' (j=31) -> rule_str[0]
        # ...
        # '00000' (j=0) -> rule_str[31]
        output_bit = rule_str[31-j]
        print(f"    {neighborhood}       |  {output_bit}")

# --- 3. KEY, RULE, AND DATA GENERATION (16-STEP) ---

def derive_one_key_verbose(input_key, key_index):
    """
    Derives a single new key from an input key using the chaotic map logic.
    Assumes input_key is 64 bytes.
    (This function is unchanged)
    """
    print(f"--- Deriving Key {key_index} (from Key {key_index - 1}) ---")
    
    if len(input_key) != 64:
        raise ValueError(f"Input key for derivation {key_index} is not 64 bytes")
    
    # Initialize variables
    GenKey = bytearray(input_key)
    W0 = 0
    KXOR = 0
    fact_sum = 0
    
    # === Step 1: Compute Initial Key-Dependent Fraction ===
    for j in range(64):
        KXOR = KXOR ^ GenKey[j]
        fact_sum = fact_sum + (GenKey[j] * KXOR)
    
    W0 = fact_sum / (2**23)
    print(f"  Key {key_index} - Initial W0: {W0:.20f}")
    
    # === Step 2: Generate Derived Key Using Chaotic Map ===
    for j in range(64):
        # Logistic map iteration
        W1 = W0 * 3.999 * (1 - W0)
        W0 = W1
        
        # Generate key byte
        Gen_Key_byte = int((W1 * (2**8) * W0)) ^ GenKey[j] ^ GenKey[j]
        GenKey[j] = Gen_Key_byte & 0xFF  # Keep only lowest byte
    
    derived_key = bytes(GenKey)
    # MODIFICATION: Print full key
    print(f"  ✓ Derived Key {key_index} generated: {derived_key.hex()}\n")
    
    return derived_key

# --- MODIFIED: 32-BIT RULE GENERATION (4-BYTE XOR FOLD) ---
def generate_ca_rule_verbose(key, key_name):
    """
    Generates a forward and backward 32-BIT CA rule from a key.
    NEW LOGIC: Divides 64-byte key into 16 4-byte parts and XORs them.
    """
    print_divider(f"Rule Generation for {key_name} (32-bit)")
    
    # MODIFICATION: Print full key
    print(f"  Using {key_name} (Full 64 bytes): {key.hex()}")
    
    if len(key) != 64:
        raise ValueError(f"Input key {key_name} is not 64 bytes")

    # Step 1: XOR Folding
    print("  Dividing 64-byte key into 16 4-byte parts and XORing...")
    
    # Initialize a 4-byte result array
    result_bytes = bytearray([0, 0, 0, 0])
    
    for i in range(16):
        start_index = i * 4
        part = key[start_index : start_index + 4]
        print(f"    Part {i:02d}: {part.hex()}")
        
        # XOR each byte of the part into the result bytes
        result_bytes[0] ^= part[0]
        result_bytes[1] ^= part[1]
        result_bytes[2] ^= part[2]
        result_bytes[3] ^= part[3]
        print(f"    -> XOR result: {result_bytes.hex()}")

    print(f"  Final 4-byte XOR result: {result_bytes.hex()}")

    # Step 2: Create Rule Pair
    # Convert the 4 bytes into a 32-bit integer
    forward_rule = int.from_bytes(result_bytes, 'big')
    
    # Backward rule is the 32-bit complement
    backward_rule = (2**32 - 1) - forward_rule
    
    # MODIFICATION: Print rules as decimal
    print(f"\n  Forward Rule ({key_name}): {forward_rule}")
    print_truth_table_5bit(forward_rule)
    
    # MODIFICATION: Print rules as decimal
    print(f"\n  Backward Rule ({key_name}): {backward_rule}")
    print_truth_table_5bit(backward_rule)
    
    return forward_rule, backward_rule

def generate_all_keys_and_rules_verbose(input_key_str):
    """
    Generates all 16 keys and 16 rule sets from a single passphrase.
    (Calls the new 32-bit rule generator)
    """
    print_divider("Master Key & Rule Generation")
    
    # --- Input Key Handling ---
    if isinstance(input_key_str, str):
        print(f"Input is a human-readable string ('{input_key_str}').")
        print("Hashing with SHA-512 to get 64-byte Main Key (Key 0).")
        key_0 = hashlib.sha512(input_key_str.encode()).digest()
    else:
        raise TypeError("Input key must be a string")
        
    # MODIFICATION: Print full key
    print(f"  Main Key (Key 0): {key_0.hex()}")
    
    all_keys = [key_0]
    all_rules = [] # This will be a list of (f_rule, b_rule) tuples
    
    # --- Generate Key 0 Rules ---
    f0, b0 = generate_ca_rule_verbose(all_keys[0], "Key 0 (Main)")
    all_rules.append((f0, b0))
    
    # --- Generate Keys 1-15 and their rules ---
    current_key = key_0
    for i in range(1, 16): # i goes from 1 to 15
        # Derive new key
        new_key = derive_one_key_verbose(current_key, i)
        all_keys.append(new_key)
        
        # Generate rules for the new key
        f_new, b_new = generate_ca_rule_verbose(new_key, f"Key {i} (Derived)")
        all_rules.append((f_new, b_new))
        
        # The new key becomes the input for the next derivation
        current_key = new_key
        
    print_divider("All 16 Rule Sets Generated")
    for i in range(16):
        # MODIFICATION: Print rules as DECIMAL and show FULL key
        print(f"  Rule Set {i:02d} (from Key {i}):")
        print(f"    -> Key: {all_keys[i].hex()}")
        print(f"    -> Fwd Rule: {all_rules[i][0]}")
        print(f"    -> Bwd Rule: {all_rules[i][1]}")
        
    return all_rules


def generate_random_data_verbose(full_plaintext_bytes):
    """
    Generates a 64-bit 'Row 0' integer from the *entire* plaintext.
    (This function is unchanged)
    """
    print_divider("Row 0 ('Random Data') Generation")
    print(f"  Input: Full plaintext ({len(full_plaintext_bytes)} bytes)")
    
    # Step 1: Hash
    print("  Hashing *entire* plaintext with SHA-26...")
    sha256_hash = hashlib.sha256(full_plaintext_bytes).digest() # 32 bytes
    print(f"  SHA-256 Hash (32 bytes): {sha256_hash.hex()}")

    # Step 2: Calculate Weighted Sum
    print("  Calculating weighted sum: Sum = (223+1)*B[0] + (223+2)*B[1] + ...")
    weighted_sum = 0
    for i in range(1, 33): # i from 1 to 32
        B_i = sha256_hash[i-1] # B_i is the (i-1)th byte
        weighted_sum += (223 + i) * B_i
    print(f"  Final Sum: {weighted_sum}")

    # Step 3: Create Fraction
    print(f"  Creating fraction: {weighted_sum} / 2^21")
    getcontext().prec = 100 
    d_sum = Decimal(weighted_sum)
    d_divisor = Decimal(2**21)
    d_fraction = d_sum / d_divisor
    print(f"  Fraction: {d_fraction}")
    
    # Step 4: Extract 64 bits
    print("  Extracting first 64 bits after decimal point...")
    frac_part = d_fraction - int(d_fraction)
    
    bits = ""
    bits_so_far = ""
    
    while len(bits) < 64:
        frac_part *= 2
        if frac_part >= 1: bit = "1"; frac_part -= 1
        else: bit = "0"
            
        bits += bit
        bits_so_far += bit
        
        # Padding rule from user: if 0 is reached, repeat sequence
        if frac_part == 0:
            if not bits_so_far: # Handle case where sum is 0
                bits = "0" * 64
                break 
            
            while len(bits) < 64:
                bits += bits_so_far
            
            bits = bits[:64] # Truncate to 64
            break
            
    bits = bits.ljust(64, '0')[:64] # Final check
    
    final_row_0_int = int(bits, 2)
    print(f"  Extracted 64 bits: {bits}")
    print(f"  Row 0 (int): {final_row_0_int}")
    print(f"  Row 0 (hex): {as_hex(final_row_0_int)}")
    return final_row_0_int

# --- 4. CORE CA LOGIC (The "Math" Function) ---

# --- MODIFIED: 5-BIT NEIGHBORHOOD (32-BIT RULE) ---
def apply_ca_step(upper_row_int, lower_row_int, f_rule, b_rule, step_name, rule_set_name):
    """
    Applies one step of the Cellular Automaton (the core logic).
    NEW LOGIC: Uses a 5-bit neighborhood and 32-bit rules.
    """
    
    print(f"\n    --- Applying CA: {step_name} (using {rule_set_name}) ---")
    print(f"    Upper Row: {as_hex(upper_row_int)}")
    print(f"    Lower Row: {as_hex(lower_row_int)}")
    
    # Print new 5-bit neighborhood header
    print("    Bit | Selector | Nbr(5)  | Rule? | Out_Bit")
    print("    ----|----------|---------|-------|---------")
    
    # Rules are 32 bits long
    f_rule_str = bin(f_rule)[2:].zfill(32)
    b_rule_str = bin(b_rule)[2:].zfill(32)
    
    upper_bits = bin(upper_row_int)[2:].zfill(64)
    lower_bits = bin(lower_row_int)[2:].zfill(64)
    
    output_bits = ""
    
    for i in range(64):
        # 1. Get Selector Bit (from upper row)
        selector = upper_bits[i]
        
        # 2. Get 5-BIT Neighborhood (from lower row, with circular padding)
        n1 = lower_bits[i-2] # i=0 -> -2 (second to last)
        n2 = lower_bits[i-1] # i=0 -> -1 (last element)
        n3 = lower_bits[i]
        n4 = lower_bits[(i+1) % 64] # i=63 -> 0 (first element)
        n5 = lower_bits[(i+2) % 64] # i=63 -> 1 (second element)
        
        neighborhood_str = n1 + n2 + n3 + n4 + n5
        neighborhood_int = int(neighborhood_str, 2) # 0 to 31
        
        # Map neighborhood int (0-31) to rule string index (0-31)
        # '11111' (31) -> index 0
        # ...
        # '00000' (0) -> index 31
        rule_index = 31 - neighborhood_int
        
        # 3. Select Rule and Get Output Bit
        if selector == '1':
            rule_type = "Fwd"
            output_bit = f_rule_str[rule_index]
        else:
            rule_type = "Bwd"
            output_bit = b_rule_str[rule_index]
        
        print(f"    {i:02d}  | {selector}        | {neighborhood_str} | {rule_type}   | {output_bit}")
        output_bits += output_bit
            
    result_int = int(output_bits, 2)
    print("    -------------------------------------------") # New divider
    print(f"    Result -> {step_name}: {as_hex(result_int)}")
    return result_int