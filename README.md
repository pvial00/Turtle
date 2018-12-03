# Turtle

***  Warning this cipher was designed for educational and entertainment purposes and should not be used in production systems

Rounds = 4

Turtle is a 128 bit block cipher that accepts a 128 bit key.  From the key, the cipher produces 4 bit swap orders for the 128 bit block, 16 round keys and four 32 bit diffusion words.  For each round, Turtle applies the bit swap permutation, XOR's the block with the block to the left of it and finally XOR's the block with round key.  This is done four times per round to make a total of 16 effective rounds.  Lastly, the diffusion word is added to each 32 bit segment of the block or (subtracted during decryption).
