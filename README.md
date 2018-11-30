# Turtle

***  Warning this cipher was designed for educational and entertainment purposes and should not be used in production systems

Turtle is a 128 bit block cipher that accepts a 128 bit key.  From the key, the cipher produces a bit swap order for block and 16 round keys.  For each round, Turtle applies the bit swap permutation, XOR's the block with the block to the left of it and finally XOR's the block with round key.  This is done four times per round.
