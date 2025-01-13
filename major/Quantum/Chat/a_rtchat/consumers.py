#!/home/ash/sage-6.2-i686-Linux/sage -python
import pdb
import itertools
import time
from sage.all import *
from channels.generic.websocket import WebsocketConsumer
from django.shortcuts import get_object_or_404
from django.template.loader import render_to_string
from asgiref.sync import async_to_sync
import json
from .models import *

load("/home/ash/main/major/Quantum/GoppaCode.sage")
load("/home/ash/main/major/Quantum/McElieceCryptosystem.sage")
load("/home/ash/main/major/Quantum/NiederreiterCryptosystem.sage")


class ChatroomConsumer(WebsocketConsumer):



    def string_to_binary_vectors(self, message, k=8):
        vectors = []
        for char in message:
            binary_rep = format(ord(char), '08b')
            binary_list = [int(bit) for bit in binary_rep]
            binary_vector = vector(GF(2), binary_list)
            vectors.append(binary_vector)
        return vectors
    

    def adjust_message_length(self, binary_list, k):
        # Pad the binary message with zeros if it's too short
        if len(binary_list) < k:
            return binary_list + [0] * (k - len(binary_list))
        # Truncate the message if it's too long
        elif len(binary_list) > k:
            return binary_list[:k]
        return binary_list



    def GetRandomMessageWithWeight(self, message_length, message_weight):
        message = matrix(GF(2), 1, message_length)
        rng = list(range(message_length))
        for i in range(message_weight):
            p = floor(len(rng)*random())
            message[0,rng[p]] = 1
            rng=rng[:p]+rng[p+1:]
        return message

    def GetGoppaPolynomial(self, polynomial_ring, polynomial_degree):
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

    def BinRepr(self, poly):
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

    def binary_to_string(self, binary_matrix):
        # Flatten the matrix into a list of binary values
        binary_list = list(binary_matrix[0])
        
        # Convert the binary list into a string of 8-bit chunks
        binary_str = ''.join(str(bit) for bit in binary_list)
        binary_values = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]
        
        # Convert each 8-bit chunk back into a character
        ascii_characters = [chr(int(bv, 2)) for bv in binary_values if len(bv) == 8]
        
        return ''.join(ascii_characters)


    def binary_to_string1(self, binary_matrix):
        # Flatten the matrix into a list of binary values
        binary_list = list(binary_matrix[0])

        # Take only the first 8 bits
        first_8_bits = binary_list[:8]
        
        # Convert the first 8 bits into a binary string
        binary_str = ''.join(str(bit) for bit in first_8_bits)
        
        # Convert the 8-bit binary string back into a character
        ascii_character = chr(int(binary_str, 2))
        
        return ascii_character

    def connect(self):
        self.user = self.scope['user']
        self.chatroom_name = self.scope['url_route']['kwargs']['chatroom_name'] 
        self.chatroom = get_object_or_404(ChatGroup, group_name=self.chatroom_name)

        async_to_sync(self.channel_layer.group_add)(
            self.chatroom_name, self.channel_name
        )

        self.accept()

    def disconnect(self, close_code):
        async_to_sync(self.channel_layer.group_discard)(
            self.chatroom_name, self.channel_name
        )
        # remove and update online users
        # if self.user in self.chatroom.users_online.all():
        #     self.chatroom.users_online.remove(self.user)
        #     self.update_online_count() 

    def receive(self, text_data):
        encrypt_list = []
        decrypt_list = []
        text_data_json = json.loads(text_data)
        body = text_data_json['body']

        m = 4
        n = 2**m
        t = 2
        delta = 2
        
        F_2m = GF(n,'Z', modulus='random')
        print ('modulus=', F_2m.modulus())
        PR_F_2m = PolynomialRing(F_2m,'X')
        Z = F_2m.gen()
        X = PR_F_2m.gen()
        irr_poly = self.GetGoppaPolynomial(PR_F_2m, t)
        goppacode = GoppaCode(n,m,irr_poly)
        generator_matrix = goppacode.generator_matrix()
        k = generator_matrix.nrows()
        binary_vectors = self.string_to_binary_vectors(body)
        error = self.GetRandomMessageWithWeight(goppacode.generator_matrix().ncols(), int(t/2))

        for vector in binary_vectors:
            matrix_form = matrix(GF(2), vector)
            encrypt_message = goppacode.Encode(matrix_form)
            ciphertext = encrypt_message + error
            encrypt_list.append(ciphertext)

        for encrypted_matrix in encrypt_list:
            decrypt_matrix = goppacode.Decode(encrypted_matrix,'Euclidean')
            # print(decrypt_matrix)
            decrypt_message = self.binary_to_string1(decrypt_matrix)
            # print(decrypt_message)
            decrypt_list.append(decrypt_message)

        message = ''.join(decrypt_list)

        message = GroupMessage.objects.create(
            body = message,
            author = self.user, 
            group = self.chatroom 
        )

        event = {
            'type': 'message_handler',
            'message_id': message.id,
        }
        async_to_sync(self.channel_layer.group_send)(
            self.chatroom_name, event
        )

    def message_handler(self, event):
        decrypt_list = []
        message_id = event['message_id']
        message = GroupMessage.objects.get(id=message_id)
        # for encrypted_matrix in self.encrypt_list:
        #     decrypt_matrix = goppacode.Decode(encrypted_matrix,'Euclidean')
        #     # print(decrypt_matrix)
        #     decrypt_message = binary_to_string1(decrypt_matrix)
        #     # print(decrypt_message)
        #     self.decrypt_list.append(decrypt_message)
        # message = str(self.decrypt_list)
        context = {
            'message': message,
            'user': self.user,
            'chat_group': self.chatroom
        }
        html = render_to_string("a_rtchat/partials/chat_message_p.html", context=context)
        self.send(text_data=html)

