import json

# Example encrypt_list
encrypt_list = [[0, 1, 1, 0, 1, 0, 0, 0], [0, 1, 1, 0, 1, 1, 0, 0]]

# Convert list to JSON string
encrypt_list_str = json.dumps(encrypt_list)

# Convert JSON string back to list
reverted_encrypt_list = json.loads(encrypt_list_str)
	
# Check if it matches the original
print("String format:", encrypt_list_str,type(encrypt_list_str))
print("Converted back to list:", reverted_encrypt_list)
print("Matches original:", encrypt_list == reverted_encrypt_list)
