## Project Description
This project implements a password-cracking tool that utilizes Rainbow Tables to reverse SHA-256 hashes. The implementation uses the RockYou wordlist (containing over 14 million passwords) to pre-compute hash chains, allowing for an efficient time-memory trade-off during the cracking process. The tool handles chain generation via sequential reduction functions and performs hash cracking by reconstructing chains to identify plaintexts for the target hashes provided in hashes.txt.

## How to Configure and Prepare the Wordlist
1. Ensure Python 3 is installed on your system.
2. Download the RockYou wordlist: `wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt`.
3. Verify the wordlist integrity: `wc -l rockyou.txt` (should return 14,344,391 lines).
4. Place hw3.py, hashes.txt, and rockyou.txt in the same working directory.

## How to Generate the Rainbow Table
1. The script generates a lookup table by creating chains of a specified length (k).
2. Run the generator with 500,000 chains and a length of 100:
   `python hw3.py --mode generate --num-chains 500000 -k 100 --wordlist-file rockyou.txt --rt-file rainbowtable.txt`
3. Verify the table was created: `ls -lh rainbowtable.txt`.
4. Inspect the first few entries: `head -n 13 rainbowtable.txt`.

## How to Run the Password Cracker
1. The crack mode uses the pre-computed rainbowtable.txt to find matches for hashes.txt.
2. Execute the cracking process using the same parameters used during generation:
   `python hw3.py --mode crack --num-chains 500000 -k 100 --hash-file hashes.txt --rt-file rainbowtable.txt`
3. The script will output each hash followed by its cracked plaintext (or None if not found).
4. The objective is to crack at least 18 of the 24 target hashes.

## Known Project Issues
1. Disk Quota Limits: On shared systems like GL, the rockyou.txt wordlist and the generated rainbow table may exceed user storage quotas.
2. Probabilistic Success: Due to the nature of rainbow tables and potential collisions, success rates depend on the number of chains; 500,000 chains are typically sufficient for 18+ cracks.
3. Memory Usage: Python dictionaries (chains_rev) are used to load the rainbow table for efficient lookups, which requires sufficient system RAM.

## LLM/AI Prompts Used
1. "Implement the reduction function R(wordlist, h, i) to map a hex hash to a wordlist index using the chain position i."
2. "Generate the logic for the crack mode to iterate through possible chain positions from k-1 down to 0."

## Sources Used
1. hashes.txt
2. HW3CMSC426.pdf
3. hw3.py
