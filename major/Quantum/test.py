message = "hello"
# Converting  to  binary vectors
binary_vectors = chat_consumer.string_to_binary_vectors(message)
# Encrypt the message using Goppa code
encrypted_message_list = []
for vector in binary_vectors:
    encrypted_message = goppacode.Encode(matrix(GF(2), vector))
    encrypted_message_list.append(encrypted_message + error)
# Decrypt the message
decrypted_message_list = []
for encrypted in encrypted_message_list:
    decrypted_vector = goppacode.Decode(encrypted, 'Euclidean')
    decrypted_message_list.append(chat_consumer.binary_to_string1(decrypted_vector))
final_message = ''.join(decrypted_message_list)
assert final_message == message 
