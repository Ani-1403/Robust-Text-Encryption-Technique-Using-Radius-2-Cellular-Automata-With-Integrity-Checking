import app as st
import os
import hashlib
from decimal import Decimal, getcontext

# --- Core CA Logic ---
# I have copied all the necessary functions from your ca_core file.
# I've made 'silent' versions (e.g., apply_ca_step_silent) 
# by removing all the 'print()' statements. This makes the app clean and fast.

# Attempt to import the core functions
try:
    from ca_core_16step_5bit_v2 import (
        BLOCK_SIZE,
        pad,
        unpad,
        as_hex,
        # We still import the *verbose* ones to use their names
        # but we will create silent versions of them.
        generate_all_keys_and_rules_verbose,
        generate_random_data_verbose,
        apply_ca_step,
        derive_one_key_verbose,
        generate_ca_rule_verbose
    )
except ImportError:
    st.error("FATAL ERROR: Could not find 'ca_core_16step_5bit_v2.py'.")
    st.info("Please make sure 'app.py' is in the same directory as 'ca_core_16step_5bit_v2.py'.")
    st.stop()


# --- Silent (Non-Verbose) Core Functions ---
# These are copies of your verbose functions but with all 'print()' calls removed
# so that they run instantly without flooding the UI.

def derive_one_key_silent(input_key, key_index):
    """Silent version of derive_one_key_verbose"""
    if len(input_key) != 64:
        raise ValueError(f"Input key for derivation {key_index} is not 64 bytes")
    GenKey = bytearray(input_key)
    W0 = 0
    KXOR = 0
    fact_sum = 0
    for j in range(64):
        KXOR = KXOR ^ GenKey[j]
        fact_sum = fact_sum + (GenKey[j] * KXOR)
    W0 = fact_sum / (2**23)
    for j in range(64):
        W1 = W0 * 3.999 * (1 - W0)
        W0 = W1
        Gen_Key_byte = int((W1 * (2**8) * W0)) ^ GenKey[j] ^ GenKey[j]
        GenKey[j] = Gen_Key_byte & 0xFF
    return bytes(GenKey)

def generate_ca_rule_silent(key, key_name):
    """Silent version of generate_ca_rule_verbose"""
    if len(key) != 64:
        raise ValueError(f"Input key {key_name} is not 64 bytes")
    result_bytes = bytearray([0, 0, 0, 0])
    for i in range(16):
        start_index = i * 4
        part = key[start_index : start_index + 4]
        result_bytes[0] ^= part[0]
        result_bytes[1] ^= part[1]
        result_bytes[2] ^= part[2]
        result_bytes[3] ^= part[3]
    forward_rule = int.from_bytes(result_bytes, 'big')
    backward_rule = (2**32 - 1) - forward_rule
    return forward_rule, backward_rule

def generate_all_keys_and_rules_silent(input_key_str):
    """Silent version of generate_all_keys_and_rules_verbose"""
    if isinstance(input_key_str, str):
        key_0 = hashlib.sha512(input_key_str.encode()).digest()
    else:
        raise TypeError("Input key must be a string")
    all_keys = [key_0]
    all_rules = [] 
    f0, b0 = generate_ca_rule_silent(all_keys[0], "Key 0 (Main)")
    all_rules.append((f0, b0))
    current_key = key_0
    for i in range(1, 16):
        new_key = derive_one_key_silent(current_key, i)
        all_keys.append(new_key)
        f_new, b_new = generate_ca_rule_silent(new_key, f"Key {i} (Derived)")
        all_rules.append((f_new, b_new))
        current_key = new_key
    return all_rules

def generate_random_data_silent(full_plaintext_bytes):
    """Silent version of generate_random_data_verbose"""
    sha256_hash = hashlib.sha256(full_plaintext_bytes).digest()
    weighted_sum = 0
    for i in range(1, 33):
        B_i = sha256_hash[i-1]
        weighted_sum += (223 + i) * B_i
    getcontext().prec = 100 
    d_sum = Decimal(weighted_sum)
    d_divisor = Decimal(2**21)
    d_fraction = d_sum / d_divisor
    frac_part = d_fraction - int(d_fraction)
    bits, bits_so_far = "", ""
    while len(bits) < 64:
        frac_part *= 2
        if frac_part >= 1: bit = "1"; frac_part -= 1
        else: bit = "0"
        bits += bit
        bits_so_far += bit
        if frac_part == 0:
            if not bits_so_far: bits = "0" * 64; break 
            while len(bits) < 64: bits += bits_so_far
            bits = bits[:64]
            break
    bits = bits.ljust(64, '0')[:64]
    return int(bits, 2)

def apply_ca_step_silent(upper_row_int, lower_row_int, f_rule, b_rule):
    """Silent version of apply_ca_step"""
    f_rule_str = bin(f_rule)[2:].zfill(32)
    b_rule_str = bin(b_rule)[2:].zfill(32)
    upper_bits = bin(upper_row_int)[2:].zfill(64)
    lower_bits = bin(lower_row_int)[2:].zfill(64)
    output_bits = ""
    for i in range(64):
        selector = upper_bits[i]
        n1 = lower_bits[i-2]
        n2 = lower_bits[i-1]
        n3 = lower_bits[i]
        n4 = lower_bits[(i+1) % 64]
        n5 = lower_bits[(i+2) % 64]
        neighborhood_str = n1 + n2 + n3 + n4 + n5
        neighborhood_int = int(neighborhood_str, 2) # 0 to 31
        rule_index = 31 - neighborhood_int
        if selector == '1':
            output_bit = f_rule_str[rule_index]
        else:
            output_bit = b_rule_str[rule_index]
        output_bits += output_bit
    return int(output_bits, 2)


# --- Refactored App Logic ---

def run_encryption(key_input, pt_string):
    """
    Takes string inputs and performs the full encryption process silently.
    Returns (row_0_hex, ct_hex, fr_hex) or (None, None, None) on error.
    """
    try:
        # --- PHASE 1: KEY & RULE GENERATION ---
        all_rules = generate_all_keys_and_rules_silent(key_input)

        # --- PHASE 2: PRE-PROCESSING ---
        pt_bytes = pt_string.encode('utf-8')
        row_0_constant = generate_random_data_silent(pt_bytes)
        padded_data = pad(pt_bytes, BLOCK_SIZE)
        
        # --- PHASE 3: ENCRYPTION (PER-BLOCK) ---
        all_ciphertext_bytes = b''
        all_residual_bytes = b''
        previous_residual_int = row_0_constant
        
        for i in range(0, len(padded_data), BLOCK_SIZE):
            rows = [] 
            current_block_bytes = padded_data[i : i + BLOCK_SIZE]
            rows.append(previous_residual_int) # rows[0]
            rows.append(int.from_bytes(current_block_bytes, 'big')) # rows[1]
            
            for step in range(16):
                f_rule, b_rule = all_rules[step]
                idx_U1 = step * 2
                idx_L1 = step * 2 + 1
                row_A = apply_ca_step_silent(rows[idx_U1], rows[idx_L1], f_rule, b_rule)
                rows.append(row_A)
                row_B = apply_ca_step_silent(rows[idx_L1], row_A, f_rule, b_rule)
                rows.append(row_B)
            
            final_ciphertext = rows[32]
            final_residual = rows[33]
            previous_residual_int = final_residual
            
            all_ciphertext_bytes += final_ciphertext.to_bytes(BLOCK_SIZE, 'big', signed=False)
            all_residual_bytes += final_residual.to_bytes(BLOCK_SIZE, 'big', signed=False)

        # --- FINAL OUTPUT ---
        row_0_hex = as_hex(row_0_constant)[2:] # Remove '0x'
        ct_hex = all_ciphertext_bytes.hex()
        fr_hex = all_residual_bytes.hex()
        
        return row_0_hex, ct_hex, fr_hex
        
    except Exception as e:
        st.error(f"Encryption Error: {e}")
        return None, None, None

def run_decryption(key_input, row_0_hex, ct_hex_str, fr_hex_str):
    """
    Takes string inputs and performs full decryption silently.
    Returns (final_message, chain_check_results, all_checks_passed)
    """
    try:
        # --- PHASE 1: KEY & RULE GENERATION ---
        all_rules = generate_all_keys_and_rules_silent(key_input)
        
        # --- GET ENCRYPTED DATA ---
        row_0_constant_expected = int(row_0_hex, 16)
        ct_bytes = bytes.fromhex(ct_hex_str)
        fr_bytes = bytes.fromhex(fr_hex_str)

        if len(ct_bytes) != len(fr_bytes) or len(ct_bytes) % BLOCK_SIZE != 0:
            st.error("Error: Data lengths are invalid or don't match.")
            return None, [], False

        # --- PHASE 4: DECRYPTION (PER-BLOCK) ---
        all_plaintext_bytes = b''
        previous_residual_expected_int = row_0_constant_expected
        all_checks_passed = True
        chain_check_results = [] 
        
        for i in range(0, len(ct_bytes), BLOCK_SIZE):
            rows = {}
            current_ct_bytes = ct_bytes[i : i + BLOCK_SIZE]
            current_fr_bytes = fr_bytes[i : i + BLOCK_SIZE]
            current_ct_int = int.from_bytes(current_ct_bytes, 'big')
            current_fr_int = int.from_bytes(current_fr_bytes, 'big')
            
            rows[32] = current_ct_int
            rows[33] = current_fr_int
            
            for step in range(15, 0, -1):
                f_rule, b_rule = all_rules[step]
                idx_U_in = step * 2 + 3
                idx_L_in = step * 2 + 2
                idx_U_out = step * 2 + 1
                idx_L_out = step * 2
                rows[idx_U_out] = apply_ca_step_silent(rows[idx_U_in], rows[idx_L_in], f_rule, b_rule)
                rows[idx_L_out] = apply_ca_step_silent(rows[idx_L_in], rows[idx_U_out], f_rule, b_rule)

            f_rule, b_rule = all_rules[0]
            row_1_rec = apply_ca_step_silent(rows[3], rows[2], f_rule, b_rule)
            row_0_rec = apply_ca_step_silent(rows[2], row_1_rec, f_rule, b_rule)
            
            all_plaintext_bytes += row_1_rec.to_bytes(BLOCK_SIZE, 'big', signed=False)
            
            if row_0_rec != previous_residual_expected_int:
                all_checks_passed = False
            
            chain_check_results.append((previous_residual_expected_int, row_0_rec))
            previous_residual_expected_int = current_fr_int

        # --- PHASE 6: FINALIZATION ---
        unpadded_data = unpad(all_plaintext_bytes, BLOCK_SIZE)
        final_message = unpadded_data.decode('utf-8')
        
        return final_message, chain_check_results, all_checks_passed
        
    except UnicodeDecodeError:
        return "(Could not decode as UTF-8 text. Data was likely binary.)", chain_check_results, all_checks_passed
    except ValueError as e:
        st.error(f"Decryption Error: {e}. This often means the key is wrong or data is corrupt.")
        return None, [], False
    except Exception as e:
        st.error(f"An unexpected error occurred: {e}")
        return None, [], False


# --- Streamlit UI ---

st.set_page_config(page_title="16-Step CA", page_icon="⚛️", layout="wide")

st.title("⚛️ 16-Step Cellular Automata Cipher")
st.markdown("A GUI for your custom 16-Step CBC-mode encryption algorithm.")

# Use tabs for a clean, minimal interface
tab1, tab2 = st.tabs(["🔒 Encrypt", "🔓 Decrypt"])

# --- ENCRYPTION TAB ---
with tab1:
    st.header("Encrypt a New Message")
    
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.subheader("Inputs")
        key_input = st.text_input("Passphrase", type="password", key="enc_key", help="Your secret key. This will be hashed to generate all 16 rule sets.")
        pt_string = st.text_area("Plaintext", "Type your secret message here...", height=200, key="enc_pt")
        
        encrypt_button = st.button("Encrypt Message", type="primary", use_container_width=True)

    with col2:
        st.subheader("Outputs")
        
        if encrypt_button:
            if not key_input:
                st.warning("Please enter a passphrase to encrypt.")
            elif not pt_string:
                st.warning("Please enter some plaintext to encrypt.")
            else:
                with st.spinner("Encrypting... (This may take a moment)"):
                    row_0_hex, ct_hex, fr_hex = run_encryption(key_input, pt_string)
                
                if row_0_hex:
                    st.success("Encryption Successful!")
                    
                    # Create the text file content
                    file_content = f"{row_0_hex}\n{ct_hex}\n{fr_hex}\n"
                    
                    st.download_button(
                        label="⬇️ Download Encryption Data",
                        data=file_content,
                        file_name="encryption_data.txt",
                        mime="text/plain",
                        use_container_width=True
                    )
                    
                    st.info("Download the file above or copy the fields below to decrypt.")
                    
                    st.text_area("Row 0 Constant (First Random Data)", row_0_hex, height=50, key="out_row0")
                    st.text_area("Ciphertext (Row 32)", ct_hex, height=150, key="out_ct")
                    st.text_area("Final Residual Data (Row 33)", fr_hex, height=150, key="out_fr")


# --- DECRYPTION TAB ---
with tab2:
    st.header("Decrypt a Message")
    
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.subheader("Inputs")
        key_input_dec = st.text_input("Passphrase", type="password", key="dec_key", help="The *exact same* secret key used to encrypt.")
        
        # File uploader
        uploaded_file = st.file_uploader("Upload encryption_data.txt", type=["txt"])
        
        # Manual paste option
        st.markdown("---")
        with st.expander("...or paste data manually"):
            man_row_0 = st.text_area("Row 0 Constant", height=50, key="man_row0")
            man_ct = st.text_area("Ciphertext (Row 32)", height=150, key="man_ct")
            man_fr = st.text_area("Final Residual Data (Row 33)", height=150, key="man_fr")

        decrypt_button = st.button("Decrypt Message", type="primary", use_container_width=True)

    with col2:
        st.subheader("Outputs")

        if decrypt_button:
            if not key_input_dec:
                st.warning("Please enter a passphrase to decrypt.")
            else:
                # Logic to load data
                row_0_to_dec, ct_to_dec, fr_to_dec = None, None, None
                
                if uploaded_file is not None:
                    try:
                        lines = uploaded_file.getvalue().decode('utf-8').splitlines()
                        if len(lines) >= 3:
                            row_0_to_dec = lines[0].strip()
                            ct_to_dec = lines[1].strip()
                            fr_to_dec = lines[2].strip()
                            st.info("Decrypting using uploaded file...")
                        else:
                            st.error("Uploaded file is invalid. It must contain 3 lines.")
                    except Exception as e:
                        st.error(f"Error reading file: {e}")
                
                elif man_row_0 and man_ct and man_fr:
                    row_0_to_dec = man_row_0.strip()
                    ct_to_dec = man_ct.strip()
                    fr_to_dec = man_fr.strip()
                    st.info("Decrypting using manually pasted data...")
                
                else:
                    st.warning("Please either upload an 'encryption_data.txt' file or paste the 3 data fields manually.")

                # If we have data, proceed with decryption
                if row_0_to_dec:
                    with st.spinner("Decrypting..."):
                        final_msg, checks, passed = run_decryption(key_input_dec, row_0_to_dec, ct_to_dec, fr_to_dec)
                    
                    if final_msg is not None:
                        if passed:
                            st.success("Decryption Successful!")
                        else:
                            st.error("Decryption FAILED! Key is wrong or data is corrupted.")
                        
                        st.text_area("Recovered Message", final_msg, height=200, key="dec_msg")
                        
                        with st.expander("View Detailed Chain Integrity Check"):
                            st.markdown("This table proves that every block was decrypted and chained correctly. If any block fails, the key is wrong.")
                            
                            # Create a clean table for the output
                            table_data = []
                            for i, (expected, recovered) in enumerate(checks):
                                status = "✓ MATCH" if expected == recovered else "✗ FAILED"
                                table_data.append({
                                    "Block": i + 1,
                                    "Status": status,
                                    "Expected Value": as_hex(expected),
                                    "Recovered Value": as_hex(recovered)
                                })
                            
                            st.dataframe(table_data, use_container_width=True)
                            
                    # If final_msg is None, an error was already shown by run_decryption