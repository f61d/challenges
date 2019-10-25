#Hacklu2019-COBOL OTP(CallMeCro)
---
To save the future you have to look at the past. Someone from the inside sent you an access code to a bank account with 
a lot of money. Can you handle the past and decrypt the code to save the future?

#Examination Site
----
* COBOL 
* Stream Cipher

#Analysis
----
Convert COBOL to python. Probably meaning as follows
```bash
with open('key.txt','r') as key_file:
    	ws_key = key_file.read() # len(ws_key) = 50

	ws_flag = ''
	ws_input = str(raw_input("Enter your message to encrypt:"))[:50]
	for i in range(50):
		ws_parse = ord(ws_input[i])
		ws_flag += chr(ord(ws_key[i])^ord(ws_input[i]))

	print ws_flag
```
Obviously,we need to blast the key and restore the plaintext.
However,if we blast the key, the blasting range is 255^50 which is a terrible number.
Therefore,we have to do something to reduce the range.

By observing,we will find a rule:the position of the character whose ascii value is greater than 127
is 0 1 3 10 11 13 20 21 23 30 31 33 40 41 43 => index % 10 == 0 | 1 | 3.
This rule shows that the key may only have 10 digits.

In addition,we found that there is a rule in ciphertext:

* No.12 byte == No.22 byte
* No.24 byte == No.34 byte
* No.26 byte == No.36 byte
* No.8 byte == No.18 byte == No.28 byte

Therefore,we will guess that the msg is the flag whose beginning may be "flag{".
According to this guess, we can get the first 5 digits of the key, as well as some of the plaintext.
```bash
flag{?????c4n_?????O2_c3?????_s4v?????fUtUr?????
```
It is easy to find this is the flag with some letters of some words.
Therefore,
We blast the key one by one, and we can judge it correctly according to the part of 
speech, and finally get the answer.

#Exploit
----
```bash
#encoding:utf-8
from string import printable

characters = ''
for i in range(33,126):
    characters += chr(i)

def filter(source_str, index):
	length = len(source_str) / 10 + 1
	for i in range(length):
		if (source_str[index + 10]) not in characters:
			return False

	return True

def pwn():
	with open("out","rb") as ws_enc:
		ws_enc.readline()
		enc = ws_enc.readline()

#################### No.6 Byte ####################
	key = ''
	guess = 'flag{'

	for i in range(len(guess)):
		key += chr(ord(guess[i])^ord(enc[i]))

	for i in range(255):
		ws_key = key + chr(i) + "????"
		result = ''
		for j in range(len(enc)):
			result += chr(ord(ws_key[j%10])^ord(enc[j]))

		if filter(result,5):
			print result
#flag{N/[WJ_c4n_bjUW|O2_c3rk_W_s4v3_kD;`fUtUrE.\nu5
#################### No.6 Byte ####################

#################### No.7 Byte ####################
	key = ''
	guess = 'flag{N'

	for i in range(len(guess)):
		key += chr(ord(guess[i])^ord(enc[i]))

	for i in range(255):
		ws_key = key + chr(i) + "???"
		result = ''
		for j in range(len(enc)):
			result += chr(ord(ws_key[j%10])^ord(enc[j]))

		if filter(result,6):
			print result
#flag{N0[WJ_c4n_buUW|O2_c3rt_W_s4v3_tD;`fUtUrE1\nu5
#################### No.7 Byte ####################

#################### No.8 Byte ####################
	key = ''
	guess = 'flag{N0'

	for i in range(len(guess)):
		key += chr(ord(guess[i])^ord(enc[i]))

	for i in range(255):
		ws_key = key + chr(i) + "??"
		result = ''
		for j in range(len(enc)):
			result += chr(ord(ws_key[j%10])^ord(enc[j]))

		if filter(result,7):
			print result
#flag{N0wWJ_c4n_buyW|O2_c3rtsW_s4v3_th;`fUtUrE1!u5
#################### No.8 Byte ####################

#################### No.9 Byte ####################
	key = ''
	guess = 'flag{N0w'

	for i in range(len(guess)):
		key += chr(ord(guess[i])^ord(enc[i]))

	for i in range(255):
		ws_key = key + chr(i) + "?"
		result = ''
		for j in range(len(enc)):
			result += chr(ord(ws_key[j%10])^ord(enc[j]))

		if filter(result,8):
			print result
#flag{N0w_J_c4n_buy_|O2_c3rts__s4v3_th3`fUtUrE1!}5
#################### No.9 Byte ####################

#################### No.10 Byte ####################
	key = ''
	guess = 'flag{Now_'

	for i in range(len(guess)):
		key += chr(ord(guess[i])^ord(enc[i]))

	for i in range(255):
		ws_key = key + chr(i)
		result = ''
		for j in range(len(enc)):
			result += chr(ord(ws_key[j%10])^ord(enc[j]))

		if filter(result,9):
			print result
#flag{Now_u_c4n_b*y_CO2_c3r+s_&_s4v3_+h3_fUtUrEn!}

#################### No.10 Byte ####################


if __name__ == '__main__':
	pwn()
```