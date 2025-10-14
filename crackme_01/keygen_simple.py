#!/usr/bin/env python3
"""
Keygen Simple - Crackme x86-64
Génère le serial pour n'importe quel username
"""

def compute_serial(username):
    """Calcule le serial pour un username donné"""
    
    # Les 3 nombres magiques du crackme
    MAGIC1 = 0x13371337
    MAGIC2 = 0xDEADBEEF
    MAGIC3 = 0xCAFEBABE
    
    # Étape 1 : Calculer le hash du username
    hash_val = 0
    
    for char in username:
        # Multiplier par 33
        hash_val = (hash_val * 33) & 0xFFFFFFFFFFFFFFFF
        
        # XOR avec le caractère
        hash_val = (hash_val ^ ord(char)) & 0xFFFFFFFFFFFFFFFF
        
        # Rotation gauche de 7 bits
        hash_val = ((hash_val << 7) | (hash_val >> 57)) & 0xFFFFFFFFFFFFFFFF
        
        # XOR avec MAGIC1
        hash_val = (hash_val ^ MAGIC1) & 0xFFFFFFFFFFFFFFFF
    
    # Étape 2 : Mixer le hash
    hash_val = hash_val ^ MAGIC2
    
    # Rotation gauche de 13 bits puis XOR
    temp = ((hash_val << 13) | (hash_val >> 51)) & 0xFFFFFFFFFFFFFFFF
    hash_val = hash_val ^ temp
    
    # XOR avec MAGIC3
    hash_val = hash_val ^ MAGIC3
    
    # Étape 3 : Garder seulement 32 bits
    hash_val = hash_val & 0xFFFFFFFF
    
    # Étape 4 : Convertir en hexadécimal (8 caractères)
    serial = f"{hash_val:08X}"
    
    return serial


# Programme principal
if __name__ == "__main__":
    print("=" * 50)
    print("  KEYGEN - Crackme x86-64")
    print("=" * 50)
    print()
    
    # Demander le username
    username = input("Username: ")
    
    # Générer le serial
    serial = compute_serial(username)
    
    # Afficher le résultat
    print()
    print("=" * 50)
    print(f"Serial: {serial}")
    print("=" * 50)
    print()
    print("Utilisez ces identifiants dans le crackme:")
    print(f"  Username: {username}")
    print(f"  Serial:   {serial}")
