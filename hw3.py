# Author: Christian Jones
# Date: March 11, 2026

import random
import hashlib
import argparse

# read_wordlist() Reads a list of possible passwords from a file
# Input:          wordlist_file; A file containing a word on each line
# Output:         wordlist; A list of words read from the wordlist file
def read_wordlist(wordlist_file):
    wordlist = []
    with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            wordlist.append(line.strip())
    return wordlist


# read_hashes() Reads a list of SHA-256 password hashes from a file
# Input:        hash_file; A file containing a hash on each line
# Output:       hashes; A set of SHA-256 hashes to crack
def read_hashes(hash_file):
    hashes = []
    with open(hash_file, "r") as f:
        for line in f:
            hashes.append(line.strip())
    return hashes


# write_rt() Writes rainbow table to a file
# Input:     rt_file; A file to write the rainbow table to
# Input:     start_words; A list of the first word in each chain
# Input:     end_words; A list of corresponding last words
# Output:    None
def write_rt(rt_file, start_words, end_words):
    with open(rt_file, "w") as f:
        for start_word, end_word in zip(start_words, end_words):
            f.write("{}\t{}\n".format(start_word, end_word))
    return


# read_rt() Reads a rainbow table from a file
# Input:    rt_file; A file containing start/end word of chain on each line
# Output:   chains; A dict of format {start_word: end_word}
def read_rt(chain_file):
    chains = {}
    with open(chain_file, "r") as f:
        for line in f:
            line = line.strip().split("\t")
            if len(line) != 2:
                continue
            start_word, end_word = line[0], line[1]
            chains[start_word] = end_word
    return chains


# H()      The hash function H
# Input:   m; The word to hash
# Output:  h; The hash digest h = H(m) in hex string format
def H(m):
    # Compute SHA-256 hash of m
    hasher = hashlib.sha256()
    hasher.update(m.encode("utf-8"))
    h = hasher.hexdigest()
    return h


# R()      The reduction function Ri
# Input:   h; SHA-256 hash digest
# Input:   i; Position in hash chain
# Output:  m; A word in the wordlist m = Ri(h)
def R(wordlist, h, i):
    # Convert SHA-256 hash digest to an integer
    h_num = int(h, 16)

    # Each position in the hash chain has a unique reduction function
    # Add i (position in chain) to h_num, then map to index in wordlist
    idx = (h_num + i) % len(wordlist)
    m = wordlist[idx]
    return m


if __name__ == "__main__":

    # Required command-line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True, choices=["generate", "crack"],
                        help="Choose the mode this program runs in")
    parser.add_argument("--num-chains", type=int, required=True,
                        help="Number of hash chains")
    parser.add_argument("-k", type=int, required=True,
                        help="The max hash chain length")

    # Optional command-line arguments
    parser.add_argument("--wordlist-file", default="rockyou.txt",
                        help="The path to the wordlist file")
    parser.add_argument("--hash-file", default="hashes.txt",
                        help="The file containing SHA-256 password hashes to crack")
    parser.add_argument("--rt-file", default="rainbowtable.txt",
                        help="The path of the rainbow table file")
    args = parser.parse_args()

    # Read the wordlist from the provided file
    wordlist = read_wordlist(args.wordlist_file)
    print("Loaded {} words from {}".format(len(wordlist), args.wordlist_file))

    # Read the list of SHA-256 hashes to crack from the provided file
    hashes = read_hashes(args.hash_file)
    print("Loaded {} SHA-256 hashes from {}".format(len(hashes), args.hash_file))

    # Generate the rainbow table
    if args.mode == "generate":

        # Randomly sample the starting word for each chain from the wordlist
        # Store the chosen starting words in the start_words list
        # Hint: Check out the random.sample() function!
        start_words = random.sample(wordlist, args.num_chains)


        # Compute the hash chain for each start word
        # Store the ending word of each in the end_words list
        end_words = []
        for start_word in start_words:
            word = start_word
            for i in range(args.k):
                h = H(word)
                word = R(wordlist, h, i)
            end_words.append(word)


        # Write hash chains to rainbow table file
        write_rt(args.rt_file, start_words, end_words)
        print("Wrote {} chains to {}".format(len(start_words), args.rt_file))


    # Crack SHA-256 hashes using a rainbow table
    elif args.mode == "crack":

        # Load rainbow table into chains dict of format {start_word: end_word}
        chains = read_rt(args.rt_file)

        # Make dict mapping the end word of each chain to its start word
        # Due to chain collisions, end_word may map to multiple start_words
        # Has format {end_word: [start_word(s)]}
        chains_rev = {}
        for start_word, end_word in chains.items():
            if chains_rev.get(end_word) is None:
                chains_rev[end_word] = []
            chains_rev[end_word].append(start_word)

        # Iterate over each hash in the list of hashes to crack
        cracked_passwds = []
        for passwd_hash in hashes:

            # Iterate over each possible position in a chain, from i = k - 1
            # down to 0
            possible_start_words = []
            for i in range(args.k-1, -1, -1):

                # Manually compute the hash chain of passwd_hash starting
                # from position i and ending at position k-1. The last word in
                # this chain will be the end_word.
                h = passwd_hash
                word = R(wordlist, h, i)
                for j in range(i + 1, args.k):
                    h = H(word)
                    word = R(wordlist, h, j)
                end_word = word


                # Check if the end word of the chain matches any end words in
                # the rainbow table. If it does, look up the start word(s) for
                # that end word and add them to possible_start_words
                if end_word in chains_rev:
                    for sw in chains_rev[end_word]:
                        if sw not in possible_start_words:
                            possible_start_words.append(sw)


            # We might have found multiple start words if collisions happened.
            # Compute the entire hash chain for each possible start word and
            # check if passwd_hash is inside of it. If it is, find the plaintext
            # that hashes to passwd_hash and store it in cracked_passwd.
            cracked_passwd = None
            for start_word in possible_start_words:
                word = start_word
                for i in range(args.k):
                    h = H(word)
                    if h == passwd_hash:
                        cracked_passwd = word
                        break
                    word = R(wordlist, h, i)
                if cracked_passwd is not None:
                    break


            # Append cracked password to cracked_passwds
            # (Or append None if we didn't find a password)
            cracked_passwds.append(cracked_passwd)

        # Print out all of the cracked passwords
        print("Cracked passwords: ")
        for passwd_hash, cracked_passwd in zip(hashes, cracked_passwds):
            print("{}\t{}".format(passwd_hash, cracked_passwd))

    else:
        print("Invalid mode, Use python hw3.py -h for help.")