# Copyright (C) 2014 by Stephen Bradshaw
#
# SHA1 and SHA2 generation routines from SlowSha https://code.google.com/p/slowsha/
# which is: Copyright (C) 2011 by Stefano Palazzo
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
# This is an edited version for educational purposes by Laurens Van Damme 2022

from re import match
from math import ceil


class Hash(object):
    '''Parent class for hash functions'''

    def hash(self, message):
        '''Normal input for data into hash function'''


        while len(message) > self._blockSize:
            self._transform(''.join([bin(ord(a))[2:].rjust(8, "0") for a in message[:self._blockSize]]))
            message = message[self._blockSize:]

        if len(message) % 64 != 0:
            raise Exception('Hashed content does not have the right length!')
        message = self.__hashBinary(message)

        for a in range(len(message) // self._b2):
            self._transform(message[a * self._b2:a * self._b2 + self._b2])

    def hexdigest(self):
        '''Outputs hash data in hexlified format'''
        return ''.join([(('%0' + str(self._b1) + 'x') % (a)) for a in self.__digest()])

    def __init__(self):
        # pre calculate some values that get used a lot
        self._b1 = self._blockSize / 8
        self._b2 = self._blockSize * 8

    def __digest(self):
        return [self.__getattribute__(a) for a in dir(self) if match('^_h\d+$', a)]

    def __setStartingHash(self, startHash):
        c = 0
        hashVals = [int(startHash[a:a + int(self._b1)], base=16) for a in range(0, len(startHash), int(self._b1))]
        for hv in [a for a in dir(self) if match('^_h\d+$', a)]:
            self.__setattr__(hv, hashVals[c])
            c += 1

    def __checkInput(self, secretLength, startHash):
        if not isinstance(secretLength, int):
            raise TypeError('secretLength must be a valid integer')
        if secretLength < 1:
            raise ValueError('secretLength must be grater than 0')
        if not match('^[a-fA-F0-9]{' + str(len(self.hexdigest())) + '}$', startHash):
            raise ValueError(
                'startHash must be a string of length ' + str(len(self.hexdigest())) + ' in hexlified format')

    def __byter(self, byteVal):
        '''Helper function to return usable values for hash extension append data'''
        if byteVal < 0x20 or byteVal > 0x7e:
            return '\\x%02x' % (byteVal)
        else:
            return chr(byteVal)

    def __binToByte(self, binary):
        '''Convert a binary string to a byte string'''
        return ''.join([chr(int(binary[a:a + 8], base=2)) for a in range(0, len(binary), 8)])

    def __hashGetExtendLength(self, secretLength, knownData, appendData):
        '''Length function for hash length extension attacks'''
        # binary length (secretLength + len(knownData) + size of binarysize+1) rounded to a multiple of blockSize + length of appended data
        originalHashLength = int(
            ceil((secretLength + len(knownData) + self._b1 + 1) / float(self._blockSize)) * self._blockSize)
        newHashLength = originalHashLength + len(appendData)
        return bin(newHashLength * 8)[2:].rjust(self._blockSize, "0")

    def __hashGetPadData(self, secretLength, knownData, appendData, raw=False):
        '''Return append value for hash extension attack'''
        originalHashLength = bin((secretLength + len(knownData)) * 8)[2:].rjust(self._blockSize, "0")
        padData = ''.join(bin(ord(i))[2:].rjust(8, "0") for i in knownData) + "1"
        padData += "0" * (((self._blockSize * 7) - (
                len(padData) + (secretLength * 8)) % self._b2) % self._b2) + originalHashLength
        if not raw:
            return ''.join(
                [self.__byter(int(padData[a:a + 8], base=2)) for a in range(0, len(padData), 8)]) + appendData
        else:
            return self.__binToByte(padData) + appendData

    def __hashBinary(self, message):
        message = ''.join(bin(ord(i))[2:].rjust(8, "0") for i in message)
        return message


class SHA1(Hash):
    def __init__(self, h0=0x67452301, h1=0xefcdab89, h2=0x98badcfe, h3=0x10325476, h4=0xc3d2e1f0):
        self._h0, self._h1, self._h2, self._h3, self._h4, = (h0, h1, h2, h3, h4)

        self._blockSize = 64

        super().__init__()

    def _pad(self, message):
        message_bin = ''.join(bin(ord(i))[2:].rjust(8, "0") for i in message)
        
        message_bin += '1'
        
        message_length = len(message) * 8

        while len(message_bin) % 512 != 448:
            message_bin += '0'

        message_bin += bin(message_length)[2:].rjust(64, '0')

        return message_bin

    def hash(self, message):
        message_bin = self._pad(message)

        for i in range(0, len(message_bin), 512):
            self._transform(message_bin[i:i+512])

    def _transform(self, chunk):

        lrot = lambda x, n: (x << n) | (x >> (32 - n))
        w = []

        for j in range(len(chunk) // 32):
            w.append(int(chunk[j * 32:j * 32 + 32], 2))

        for i in range(16, 80):
            w.append(lrot(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
                     & 0xffffffff)

        a = self._h0
        b = self._h1
        c = self._h2
        d = self._h3
        e = self._h4

        for i in range(80):

            if i <= i <= 19:
                f, k = d ^ (b & (c ^ d)), 0x5a827999
            elif 20 <= i <= 39:
                f, k = b ^ c ^ d, 0x6ed9eba1
            elif 40 <= i <= 59:
                f, k = (b & c) | (d & (b | c)), 0x8f1bbcdc
            elif 60 <= i <= 79:
                f, k = b ^ c ^ d, 0xca62c1d6

            temp = lrot(a, 5) + f + e + k + w[i] & 0xffffffff
            a, b, c, d, e = temp, a, lrot(b, 30), c, d

        self._h0 = (self._h0 + a) & 0xffffffff
        self._h1 = (self._h1 + b) & 0xffffffff
        self._h2 = (self._h2 + c) & 0xffffffff
        self._h3 = (self._h3 + d) & 0xffffffff
        self._h4 = (self._h4 + e) & 0xffffffff
