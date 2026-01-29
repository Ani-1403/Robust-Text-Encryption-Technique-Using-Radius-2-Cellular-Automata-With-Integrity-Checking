import os
import math
import hashlib
from Crypto.Cipher import AES, DES

# Import functions from your custom CA files
try:
    # We are importing the *verbose* functions from the new v2 file
    from ca_core_16step_5bit_v2 import (
        BLOCK_SIZE as CA_BLOCK_SIZE,
        pad as ca_pad,
        generate_all_keys_and_rules_verbose,
        generate_random_data_verbose,
        apply_ca_step,
        print_divider
    )
except ImportError:
    # --- MODIFIED: Updated error message to point to the correct file ---
    print("Error: Could not find 'ca_core_16step_5bit_v2.py'.")
    print("Please make sure all program files are in the same directory.")
    exit()
    
# Import functions from the new cipher files
# These files (des_cipher.py, aes_cipher.py) must be in the same directory
try:
    import des_cipher
    import aes_cipher
except ImportError:
    print("Error: Could not find 'des_cipher.py' or 'aes_cipher.py'.")
    print("Please make sure all program files are in the same directory.")
    exit()

# --- 1. CORRELATION FUNCTION ---

def calculate_correlation(data1, data2):
# ... existing code ...
    """
    Calculates the Pearson correlation coefficient between two byte strings.
    Makes data1 and data2 the same length by padding the shorter one.
    """
    len1, len2 = len(data1), len(data2)
    
    # Pad the shorter list to match the longer one
# ... existing code ...
    if len1 < len2:
        data1 += b'\x00' * (len2 - len1)
    elif len2 < len1:
        data2 += b'\x00' * (len1 - len2)
# ... existing code ...
    
    n = len(data1)
    if n == 0 or n != len(data2):
# ... existing code ...
        print("Error: Data lengths for correlation are invalid.")
        return 0.0

    mean1 = sum(data1) / n
    mean2 = sum(data2) / n
# ... existing code ...
    
    covariance_sum = 0.0
    std_dev1_sum = 0.0
    std_dev2_sum = 0.0
# ... existing code ...
    
    for i in range(n):
        diff1 = data1[i] - mean1
        diff2 = data2[i] - mean2
# ... existing code ...
        
        covariance_sum += (diff1 * diff2)
        std_dev1_sum += diff1 ** 2
        std_dev2_sum += diff2 ** 2
# ... existing code ...
        
    denominator = math.sqrt(std_dev1_sum) * math.sqrt(std_dev2_sum)
    
    if denominator == 0:
# ... existing code ...
        return 1.0 if std_dev1_sum == std_dev2_sum else 0.0
        
    correlation = covariance_sum / denominator
    return correlation

# --- 2. YOUR 16-STEP CA ENCRYPTION (as an importable function) ---

def encrypt_ca_16_step(passphrase, plaintext_bytes):
# ... existing code ...
    """
    Runs your full 16-step CA encryption.
    This is the logic from your encrypt_16step.py,
    re-written to be an importable function.
    
    NOTE: This version IS VERBOSE, as requested.
    """
    print_divider("Running Your 16-Step CA Encryption")
# ... existing code ...
    
    # --- PHASE 1: KEY & RULE GENERATION ---
    # Call the verbose function (default verbose=True)
    all_rules = generate_all_keys_and_rules_verbose(passphrase)
# ... existing code ...
    
    # --- PHASE 2: PRE-PROCESSING ---
    # Call the verbose function (default verbose=True)
    row_0_constant = generate_random_data_verbose(plaintext_bytes)
    padded_data = ca_pad(plaintext_bytes, CA_BLOCK_SIZE)
# ... existing code ...
    
    # --- PHASE 3: ENCRYPTION (PER-BLOCK) ---
    all_ciphertext_bytes = b''
    all_residual_bytes = b''
# ... existing code ...
    
    for i in range(0, len(padded_data), CA_BLOCK_SIZE):
        rows = [] 
        current_block_bytes = padded_data[i : i + CA_BLOCK_SIZE]
# ... existing code ...
        rows.append(row_0_constant) # rows[0]
        rows.append(int.from_bytes(current_block_bytes, 'big')) # rows[1]
        
        # --- 16-STEP ASYMMETRIC CHAIN ---
        for step in range(16):
# ... existing code ...
            f_rule, b_rule = all_rules[step]
            rule_set_name = f"Rule Set {step}"
            
            idx_U1 = step * 2
            idx_L1 = step * 2 + 1
# ... existing code ...
            
            step_name_1 = f"Row {step * 2 + 2:02d}"
            # Call the verbose function (default verbose=True)
            row_A = apply_ca_step(rows[idx_U1], rows[idx_L1], f_rule, b_rule, 
                                  step_name_1, rule_set_name)
# ... existing code ...
            rows.append(row_A)
            
            step_name_2 = f"Row {step * 2 + 3:02d}"
            # Call the verbose function (default verbose=True)
            row_B = apply_ca_step(rows[idx_L1], row_A, f_rule, b_rule, 
                                  step_name_2, rule_set_name)
# ... existing code ...
            rows.append(row_B)

        all_ciphertext_bytes += rows[32].to_bytes(CA_BLOCK_SIZE, 'big', signed=False)
        all_residual_bytes += rows[33].to_bytes(CA_BLOCK_SIZE, 'big', signed=False)
# ... existing code ...
        
    print("  ...Your CA Encryption: COMPLETE")
    return all_ciphertext_bytes # Only return the main ciphertext

# --- 3. MAIN RUNNER PROGRAM ---

def main():
# ... existing code ...
    print_divider("MASTER CIPHER ANALYZER")
    
    # --- PHASE 1: GENERATE COMMON DATA ---
    print_divider("Generating Common Plaintext and Keys")
# ... existing code ...
    
    # 1. Generate Plaintext
    plaintext_string = "The sun rose slowly over the eastern ridge and spilled gold across the valley floor. Frost still clung to the blades of grass so each blade looked like a tiny spear of glass. A single lark climbed the sky singing as if the whole world were listening only to her. Down below the farmhouse chimney puffed its first thin ribbon of smoke and the smell of burning pine drifted through the morning air. Inside the kitchen the old iron stove cracked and popped as flames found their breakfast of kindling. Clara stood at the sink scraping last nights plates and humming a tune her mother used to hum before the war. She wore the blue apron with the faded cornflowers and her hair was twisted into a knot that would come undone by noon. On the table a bowl of eggs waited next to a slab of butter softening in its dish. Through the window she saw the dog trotting up the lane with something dark in its mouth probably a boot someone lost in the night. She wiped her hands on a towel and stepped onto the porch boards creaking under her weight. The dog dropped the boot at her feet tail wagging proud as a knight offering tribute. Clara bent down patted his head and told him he was a good brave fool. The boot was cracked and muddy size eleven mens left foot. She set it on the railing wondering whose story had ended with a missing shoe. Back inside she cracked three eggs into the skillet and watched the whites swirl and set. She thought about the letter hidden in her dresser drawer the one with the foreign stamp and the single line I am still alive. It had arrived three Tuesdays ago and she had not yet answered because words felt too small for what she needed to say. The butter hissed and she flipped the eggs sliding them onto a tin plate. She ate standing up looking out the window at the ridge where the sun now stood full and bright. A hawk circled high and silent scanning the frostbitten fields for anything that moved. Clara finished her breakfast washed the plate and hung the towel to dry. She took the boot outside set it on the steps and told the dog to keep watch. Then she walked to the barn the gravel cold under her bare feet. Inside smelled of hay and oil and the warm breath of horses. The chestnut mare nickered when she saw her and Clara stroked the velvet nose whispering good morning girl. She filled the manger with oats and checked the water trough breaking the thin ice that had formed overnight. While the mare ate Clara climbed the ladder to the loft and pulled back the tarp that covered the old trunk. The hinges groaned as she lifted the lid revealing the uniform folded neat as a flag. She touched the sleeve feeling the rough wool still holding the shape of the shoulder that had worn it. Beneath the jacket lay the field notebook wrapped in oilcloth. She opened it and read the last entry dated the day before the river crossing. The handwriting was hurried but legible. We move at dawn pray for fog. She closed the book held it to her chest and listened to the mare munching below. After a minute she wrapped the notebook again set it back inside and closed the trunk. The loft window faced west and she saw clouds building along the horizon dark and bruised. Weather coming she thought and climbed down. She forked fresh hay into the stall then latched the door and stepped back into the yard. The dog had not moved from the boot. She scratched his ears told him he was on duty and went inside to dress. The mirror showed her a woman older than thirty but not yet forty eyes the color of river stone and a mouth that had forgotten how to smile on command. She brushed her hair until the knots surrendered then wound it into a braid and pinned it tight. She chose the gray skirt and the white blouse with the high collar because it made her feel like a schoolteacher which she had once been before the fields needed her more than the children. She laced her boots and took the letter from the drawer slipping it into her pocket like a small explosive. Outside the wind had picked up rattling the porch swing. She called the dog and together they walked the lane toward the road that led to town. The gravel turned to dirt and the dirt to pavement and soon she heard the distant hum of the only truck that ever passed this early. It belonged to the postman who drank coffee by the gallon and spoke only when spoken to first. She waved and he lifted two fingers from the wheel in reply. The town was three miles of walking and she used the time to practice the words she might write. Dear Henry I received your letter and I do not know whether to believe it. Or maybe Henry the dog brought home a boot today and I thought of you. Or simply Henry come home the frost is thicker every morning. None of them sounded right so she kept walking letting the rhythm of her steps decide. The town appeared as a cluster of roofs and a water tower painted pale green. The post office was also the general store and the gas station and the place where old men played dominoes on Saturday nights. She pushed through the door setting the bell above it jangling. Mrs Haskell looked up from her crossword and said morning Clara. Clara nodded and walked to the counter pulling the envelope from her pocket. She bought a single stamp with a coin warm from her palm and asked for a pen. Mrs Haskell slid one across the scarred wood. Clara stared at the blank paper then wrote the date in the corner. She hesitated another second then wrote I will wait one more season if the river freezes I will walk across it. She signed her name folded the sheet sealed it and pressed the stamp hard as if she could make it stick forever. Mrs Haskell took the letter weighed it and dropped it into the sack with the rest of outbound words. Clara bought a spool of thread and a loaf of bread because it felt wrong to leave with nothing practical. Outside the wind had shifted carrying the smell of snow. She tucked the bread under her arm and started home. Halfway there the first flake landed on her sleeve and she watched it melt into a perfect tiny star. By the time she reached the farm the ridge was invisible behind white curtains. She gathered eggs closed the shutters and lit the stove for the long afternoon. The dog curled on the rug and she sat at the table with paper and ink deciding finally that tomorrow she would write the rest of the letter the part that explained how a woman keeps a heart open like a window even in winter."
    plaintext_bytes = plaintext_string.encode('utf-8')
    print(f"  Plaintext: '{plaintext_string[:50]}...' ({len(plaintext_bytes)} bytes)")
# ... existing code ...
        # 2. Generate a "Master Passphrase" for all keys
    passphrase = "my-super-secret-password-for-testing-123!"
    print(f"  Master Passphrase: '{passphrase}'")
    
    # 3. Derive all necessary keys
# ... existing code ...
    master_key_64 = hashlib.sha512(passphrase.encode()).digest()
    
    # Your CA cipher uses the passphrase directly
    ca_key = passphrase
# ... existing code ...
    
    # DES key (8 bytes)
    des_key = master_key_64[:8]
    
    # AES-256 key (32 bytes)
# ... existing code ...
    aes_key = master_key_64[:32]
    
    print(f"  CA Key: (Passphrase)")
    print(f"  DES Key (8 bytes): {des_key.hex()}")
# ... existing code ...
    print(f"  AES Key (32 bytes): {aes_key.hex()}")
    
    # --- PHASE 2: RUN ENCRYPTIONS ---
    print_divider("Running All Encryptions")
# ... existing code ...
    
    print("\n1. Running Your 16-Step CA Cipher...")
    # This will now be verbose
    ca_ciphertext = encrypt_ca_16_step(ca_key, plaintext_bytes)
# ... existing code ...
    print(f"  CA Ciphertext (first 32 bytes): {ca_ciphertext[:32].hex()}...")

    print("\n2. Running DES Cipher...")
    des_ciphertext = des_cipher.encrypt(des_key, plaintext_bytes)
# ... existing code ...
    print("  DES Encryption: COMPLETE")
    print(f"  DES Ciphertext (first 32 bytes): {des_ciphertext[:32].hex()}...")

    print("\n3. Running AES-256 Cipher...")
# ... existing code ...
    aes_ciphertext = aes_cipher.encrypt(aes_key, plaintext_bytes)
    print("  AES Encryption: COMPLETE")
    print(f"  AES Ciphertext (first 32 bytes): {aes_ciphertext[:32].hex()}...")
    
    # --- PHASE 3: CORRELATION ANALYSIS ---
# ... existing code ...
    print_divider("Correlation Analysis (Plaintext vs. Ciphertext)")
    print(" (Ideal correlation is 0.0)")
    
    # 1. Your CA
# ... existing code ...
    corr_ca = calculate_correlation(plaintext_bytes, ca_ciphertext)
    print(f"\n  Your 16-Step CA: {corr_ca:+.10f}")
    
    # 2. DES
    corr_des = calculate_correlation(plaintext_bytes, des_ciphertext)
# ... existing code ...
    print(f"  DES:               {corr_des:+.10f}")
    
    # 3. AES
    corr_aes = calculate_correlation(plaintext_bytes, aes_ciphertext)
# ... existing code ...
    print(f"  AES-256:           {corr_aes:+.10f}")
    
    print_divider("Analysis Complete")

    # --- NEW: FINAL SUMMARY OF INPUTS (as requested) ---
# ... existing code ...
    print_divider("Test Inputs Used")
    print(f"  Plaintext: {plaintext_string}")
    print(f"  Master Passphrase: {passphrase}")
    print(f"  DES Key (8 bytes): {des_key.hex()}")
# ... existing code ...
    print(f"  AES Key (32 bytes): {aes_key.hex()}")
    print(f"  CA Key: (Used Passphrase directly)")


if __name__ == "__main__":
# ... existing code ...
    try:
        main()
    except (ImportError, ModuleNotFoundError) as e:
        print("\n" + "="*70)
        # Check if the error is for Crypto or our local files
        if 'Crypto' in str(e):
            print("!! ERROR: Missing 'pycryptodome' library.")
            print("!! Please install it by running: pip install pycryptodome")
        else:
            print(f"!! ERROR: Missing a required file: {e}")
            print("!! Make sure all .py files are in the same directory.")
        print("="*70)
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")