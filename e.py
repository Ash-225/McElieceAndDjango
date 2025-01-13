#!/home/ash/sage-6.2-i686-Linux/sage -python

import pdb
import itertools
import time
import json
from sage.all import *

"""
############################################
#Functions & Classes to Import
############################################
"""
load("major/Quantum/GoppaCode.sage")
load("major/Quantum/McElieceCryptosystem.sage")
load("major/Quantum/NiederreiterCryptosystem.sage")


body = input("ENTER : \n")


def receive(self, text_data):
    # text_data_json = json.loads(text_data)
    
	
    encrypted_body = encrypt_message(body)


    l = len(body)
	
    message = GroupMessage.objects.create(
        body = encrypted_body,
        # author = self.user, 
        # group = self.chatroom,
		original_length = l,
        )

    event = {
        'type': 'message_handler',
        'message_id': message.id,
        }
    async_to_sync(self.channel_layer.group_send)(
        self.chatroom_name, event
        )

    return l

def string_to_binary_vectors(message, k=8):
    vectors = []
    for char in message:
        binary_rep = format(ord(char), '08b')
        binary_list = [int(bit) for bit in binary_rep]
        binary_vector = vector(GF(2), binary_list)
        vectors.append(binary_vector)
    return vectors




def adjust_message_length(binary_list, k):
    # Pad the binary message with zeros if it's too short
    if len(binary_list) < k:
        return binary_list + [0] * (k - len(binary_list))
    # Truncate the message if it's too long
    elif len(binary_list) > k:
        return binary_list[:k]
    return binary_list



def GetRandomMessageWithWeight(message_length, message_weight):
	message = matrix(GF(2), 1, message_length)
	rng = list(range(message_length))
	for i in range(message_weight):
		p = floor(len(rng)*random())
		message[0,rng[p]] = 1
		rng=rng[:p]+rng[p+1:]
	return message

def GetGoppaPolynomial(polynomial_ring, polynomial_degree):
	while 1:
		irr_poly = polynomial_ring.random_element(polynomial_degree)
		irr_poly_list = irr_poly.list() 
		irr_poly_list[-1] = 1
		irr_poly = polynomial_ring(irr_poly_list)
		if irr_poly.degree() != polynomial_degree:
			continue
		elif irr_poly.is_irreducible():
			break				
		else :
			continue
	
	return irr_poly

def BinRepr(poly):
    try: 
        poly_ls = list(poly)
    except TypeError:
        # For individual finite field elements, check if it's an integer modulo type
        if isinstance(poly, sage.rings.finite_rings.integer_mod.IntegerMod_int):
            bin_repr = bin(int(poly))[2:]  # Directly convert to integer
        else:
            # Convert finite field element to integer directly
            bin_repr = bin(poly.integer_representation())[2:]
        bin_repr = bin_repr[::-1]
        print(bin_repr)
        return
    else: 
        for _ in poly_ls:
            # Handle integer modulo types
            if isinstance(_, sage.rings.finite_rings.integer_mod.IntegerMod_int):
                bin_repr = bin(int(_))[2:]  # Directly convert to integer
            else:
                # Convert finite field element to integer
                bin_repr = bin(_.integer_representation())[2:]
            bin_repr = bin_repr[::-1]
            print(bin_repr)

def binary_to_string(binary_matrix):
    # Flatten the matrix into a list of binary values
    binary_list = list(binary_matrix[0])
    
    # Convert the binary list into a string of 8-bit chunks
    binary_str = ''.join(str(bit) for bit in binary_list)
    binary_values = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]
    
    # Convert each 8-bit chunk back into a character
    ascii_characters = [chr(int(bv, 2)) for bv in binary_values if len(bv) == 8]
    
    return ''.join(ascii_characters)




def binary_to_string1(binary_matrix):
    # Flatten the matrix into a list of binary values
    binary_list = list(binary_matrix[0])

    # Take only the first 8 bits
    first_8_bits = binary_list[:8]
    
    # Convert the first 8 bits into a binary string
    binary_str = ''.join(str(bit) for bit in first_8_bits)
    
    # Convert the 8-bit binary string back into a character
    ascii_character = chr(int(binary_str, 2))
    
    return ascii_character

option = 'GoppaCode'
# option = 'McElieceCryptosystem'



for k in range(1):
	
	# setup system parameters (m,n,t, goppa_polynomial)
	encrypt_list=[]
	decrypt_list = []
	m = 4
	n = 2**m
	t = 2
	delta = 2
	#construct finite field and its extension[[1 1 0 1 1 0 0 0 1]]
	#P = PolynomialRing(GF(2),'M') x = P.gen() f = 1+x+x**3+x**4+x**8
	F_2m = GF(n,'Z', modulus='random')
	print ('modulus=', F_2m.modulus())
	PR_F_2m = PolynomialRing(F_2m,'X')
	Z = F_2m.gen()
	X = PR_F_2m.gen()
		
	for _ in range(1):	
		irr_poly = GetGoppaPolynomial(PR_F_2m, t)
		#irr_poly = PR_F_2m([F_2m([1,0,1,1,0,0,1]),F_2m([1,0,0,0,1,0,1,1]),F_2m([0,0,1,0,0,0,1,1]),F_2m([1,1,0,0,0,1,0,1]),F_2m([1,0,1,0,0,1]),F_2m([0,1,1,1,1,0,1,1]),F_2m([1,1,0,1,0,1,1]),F_2m([1,1,1,1,1,0,0,1]),F_2m([0,1,0,0,0,1,0,1]),F_2m([0,1,0,0,0,1,1,1]),F_2m([0,1,0,1,1,1,1]),F_2m([1,0,0,0,1,1,1,1]),F_2m([0,1,1]),F_2m([0,0,1,0,1,0,1,1]),F_2m([1,0,0,1,1,0,1]),F_2m([0,0,0,1,1,0,1,1]),F_2m([0,1,1,1,1,1]),F_2m([0,0,0,1,0,0,1]),F_2m([0,0,1,1,0,0,1]),F_2m([0,1,0,0,1]),F_2m([1,1,0,0,1]),F_2m([1,1,1,1,1,0,1]),F_2m([0,0,0,1]),F_2m([1,0,1,1,0,0,0,1]),F_2m([1,0,1,0,0,0,0,1]),F_2m([0,1,1,0,1]),F_2m([1,0,0,0,0,0,0,1]),F_2m([1,0,0,1,1,0,1]),F_2m([1,1,0,1,1,1]),F_2m([1,0,1,1,0,1,1,1]),F_2m([1,0,1,1,0,1,1,1]),F_2m([1])])#TODO
		#irr_poly = irr_poly*irr_poly
		#t = t*2		
		print ('m=%d, n=%d, t=%d' %(m,n,t))	
		print ('Goppa-polynomial:',irr_poly)

		if option == 'GoppaCode':
			encrypt_list_matrix= []
			goppacode = GoppaCode(n,m,irr_poly)
			#Decoding GoppaCode using classic matrix form.
			#Get a random message and encrypt it.
			#message = matrix(GF(2),[0, 1, 0, 0, 1, 0, 0, 0])
			# codeword = goppacode.Encode(binary_body)
			# Get generator matrix and its dimensions
			generator_matrix = goppacode.generator_matrix()
			k = generator_matrix.nrows()

			# Convert body to binary matrix with adjusted length
			binary_vectors = string_to_binary_vectors(body)

			# Encode the message
			error = GetRandomMessageWithWeight(goppacode.generator_matrix().ncols(), int(t/2))

			# binary_body = string_to_binary_matrix(body)  # Convert body to binary matrix
			for vector in binary_vectors:
				matrix_form = matrix(GF(2), vector)
				encrypt_message = goppacode.Encode(matrix_form)
				ciphertext = encrypt_message + error
				print(ciphertext,"pp")
				encrypt_list.append([list(row) for row in ciphertext.rows()])
			length_of_encrypt_list = len(encrypt_list)
			for i in range(length_of_encrypt_list):
				flattened_encrypt_list = [row[0] for row in encrypt_list]
				encrypt_list_matrix.append(flattened_encrypt_list)
			print(encrypt_list)
			print(flattened_encrypt_list,"pppppppppp")
			print(encrypt_list_matrix)
			# encrypt_list_str = json.dumps(encrypt_list)

			# encrypt_matrix = matrix(GF(2), flattened_encrypt_list)
			# print(encrypt_matrix_as_list_of_tuples,"-----------------------------")
			for encrypted_matrix in encrypt_list_matrix:
				decrypt_matrix = goppacode.Decode(encrypted_matrix,'Euclidean')
				print(decrypt_matrix)
				decrypt_message = binary_to_string1(decrypt_matrix)
				print(decrypt_message)
				decrypt_list.append(decrypt_message)

			                       
			#error = matrix(GF(2),[0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,1,0,0,1,1,0,0,0,0,1,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,1,0,0,0,1,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,1,0,0,0,0,1,0,1,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,1])
				
				
			print ('random message is:', body)
			print ('codeword is:', encrypt_list)
			print ('error is:', error.str())
			print ('decrypted_msg:', decrypt_list)

			# print ('ciphertext is:', ciphertext.str())
			
			#Decrypt the ciphertext using algebraic syndrome decoding algorihtm 
			# recoveredtext1 = goppacode.Decode(ciphertext,'Euclidean')
			
			# #Decrypt the ciphertext using classic syndrome decoding algorithm
			# g = goppacode.goppa_polynomial()	
			# X = g.parent().gen()		
			# syndrome = goppacode.parity_check_matrix()*ciphertext.transpose()		
			# syndrome_poly = 0		
			# for i in range(t):
			# 	tmp = []
			# 	for j in range(m):
			# 		tmp.append(syndrome[i*m+j,0])
		                
			# 	syndrome_poly += F_2m(tmp[::1])*(X**i)
			# print ('syndrome_poly=', BinRepr(syndrome_poly))
			# recoveredtext2 = goppacode.SyndromeDecode(syndrome_poly,'Euclidean')
			
			# sigma = 1	
			# for i in range(error.ncols()):
			# 	if (error[0,i] == 1):
			# 		sigma = sigma*(X-goppacode._codelocators[i])
			# print ('sigma= ',sigma)
			# omega = 0 
			# for i in range(error.ncols()):
			# 	if (error[0,i] == 1):
			# 		tmp = sigma/(X-goppacode._codelocators[i])
			# 		omega = omega+tmp
			# recoveredtext1 = binary_to_string(recoveredtext1.str())

					

			# print ('recovered message1 is:', recoveredtext1.str())
			# # print ('recovered message1 is:', recoveredtext1)
			# print ('recovered message2 is:', recoveredtext2.str())
			
			# if recoveredtext1 == codeword and recoveredtext2+ciphertext == codeword:
			# 	print ('It works!')
			# else :
			# 	print ('Something wrong!')
			# 	for i in range(len(goppacode._codelocators)):
			# 		if goppacode._codelocators[i] == 1:
			# 			print ('codelocators',i+1)
			# 	raw_input('look at here!')


		elif option == 'McElieceCryptosystem':
			# vectors = []
			crypto = McElieceCryptosystem(n,m,irr_poly)
			generator_matrix = crypto.goppa_code().generator_matrix()
			k = generator_matrix.nrows()
			# print(body)
			#Get a random message and encrypt it.
			binary_vectors = string_to_binary_vectors(body)
			# message = GetRandomMessage(crypto.goppa_code().generator_matrix().nrows())
			for vector in binary_vectors:
				matrix_form = matrix(GF(2), vector)
				encrypted_message = crypto.Encrypt(matrix_form)
				encrypt_list.append(encrypted_message)
			# print(encrypt_list)
			#Decrypt the secret message
			for encrypted_matrix in encrypt_list:
				decrypted_matrix = crypto.Decrypt(encrypted_matrix)  # Ensure this is the right form
				decrypted_message = binary_to_string(decrypted_matrix)  # Convert back to string
				decrypt_list.append(decrypted_message)

			print(f"Binary representation of input: {binary_vectors}")
			print( 'random msg:', binary_vectors)
			print ('encrypted msg:', encrypt_list)
			print ('decrypted_msg:', decrypt_list)
			# if body == decrypted_message:
			# 	print ('It works!')
			# else :
			# 	print ('Something wrong!')
			# 	input('look at here!')
			#Encrypt & Decrypt			
			#Get m*t-bits random message weighing at most t and encrypt it.