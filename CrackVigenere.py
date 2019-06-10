#!/usr/bin/python

import optparse
import os
import sys
import itertools
from string import ascii_uppercase, ascii_lowercase


# Get Options
parser = optparse.OptionParser()

parser.add_option('-f',
                  dest="file",
                  default='',
                  help='define a file containing the encoded cipher text',
                 )
parser.add_option('-t',
                  dest="text",
                  default='',
                  help='define the encoded cipher text as text directly within the command',
                 )
parser.add_option('-w',
                  dest="wordlist",
                  default='',
                  help='define a wordlist to be used in the dictionary attack. This should be a text file with one key per line.',
                 )
parser.add_option('-k',
                  dest="known",
                  default='',
                  help='define a known string that will be in the decoded output.',
                 )
parser.add_option('-l',
                  dest="language",
                  default='en',
                  help='If detecting language, define a two-letter language code (default "en" - English)',
                 )
parser.add_option('-m',
                  dest="matchThreshold",
                  default=0.99,
                  help='If detecting language, use this option to set a custom success threshold between 0 and 1. (default 0.99)',
                 )
parser.add_option('-v',
                  dest="verbose",
                  default=False,
                  action="store_true",
                  help='show verbose output',
                 )
parser.add_option('-V',
                  dest="vverbose",
                  default=False,
                  action="store_true",
                  help='show more verbose output (show decoded text for each key in wordlist)',
                 )

parser.set_usage("""Usage: python CrackVigenere.py -f <encoded file> -w <wordlist>

Examples:
python CrackVigenere.py -f encoded.txt -w wordlist.txt
python CrackVigenere.py -t 'Ifx xivri uycjc dhe xhbnl vjrg ral znow wvu.' -w wordlist.txt -k 'lazy dog.'

Vigenere Decoder Script

A Vigenere cipher is like a normal substitution cipher (caesar / rot13 / etc) with the added complexity of a secret key. This key is repeated over the length of the cipher text to encode each character differently. Vigenere ciphers can be decoded a number of ways, usually requiring some assumed knowledge of what the output is supposed to be. For example, if the encoded cipher text is relatively long (more than 50-100 characters) and you assume the output to consist of english words, you can use letter frequency analysis techniques to decode the text. Additionally, as long as you have some type of idea what the output will look like (either a specific, unique string or simply that the output will be in plain english), you can brute force the key using a dictionary attack.

This script utilizes a dictionary attack method to crack the Vigenere key and decode the cipher text. In order for the script to know that it has successfully decoded the message, define the -k (--known) variable with a unique string that you know will be included in the decoded output. Ideally, this string is long (>4 characters) or else the script may match incorrectly. If this variable is not defined, the script will default to looking for english words as a way of defining success.""")

options, remainder = parser.parse_args()

infile = options.file
intext = options.text
wordlist = options.wordlist
knownstring = options.known
language = options.language
matchThreshold = float(options.matchThreshold)
verbose = options.verbose
vverbose = options.vverbose

if infile:
  # default to using an input file as cipher text if provided
  if os.path.isfile(infile):
    try:
      with open(infile, 'r') as f:
        ciphertext = f.read()
    except:
      print("[Error] Could not read cipher text file")
      raise
      sys.exit()
  else:
    print("[Error] Could not find file '%s'" % infile)
    sys.exit()
elif intext:
  # use text input for cipher text
  ciphertext = str(intext)
else:
  # no input cipher submitted
  print("[Error] Please define cipher text with '-f' or '-t'. Use '-h' option for help.")
  sys.exit()

# make sure wordlist option is defined
if wordlist:
  # make sure word list file exists
  if os.path.isfile(wordlist):
    # open word list file and store as variable
    try:
      fo = open(wordlist)
      words = fo.readlines()
      fo.close()
    except:
      print("[Error] Unable to load wordlist")
      raise
  else:
    print("[Error] Could not find wordlist file '%s'" % wordlist)
    sys.exit()
else:
  print("[Error] Please define a wordlist with '-w'. Use '-h' option for help.")
  sys.exit()


if not knownstring:
  try:
    import langdetect
    # set seed to 0 to enforce consistent results
    langdetect.DetectorFactory.seed = 0
    if verbose: print("[DEBUG] Successfully imported langdetect module")
  except:
    print("[Error] prerequisite required to automatically detect English. Install with 'pip install langdetect' or use the -k option to manually define a search string. Use -h for help.")
    sys.exit()

if not len(language) == 2:
  print("[Error] language must be a 2-character code (Ex. 'en' for English)")
  sys.exit()

if vverbose: verbose = True


def _key_gen(plain_text, key):
  key_string = []
  key_length = len(plain_text)
  key_mapper =  dict(itertools.izip(range(1,27), itertools.izip(ascii_lowercase, ascii_uppercase)))

  for i in range(key_length):
    index = i % len(key)
    for k, v in key_mapper.items():
      if key[index] in v:
        key_string.append(k)

  return key_string


def v_decipher(cipher, key):

  generated_key = _key_gen(cipher, key)

  deciphered_string = []

  key_index = 0
  for cipher_index in range(len(cipher)):
    if cipher[cipher_index].isalpha():
      num = ord(cipher[cipher_index])
      num += -generated_key[key_index] + 1
      key_index += 1

      if cipher[cipher_index].isupper():
        if num > ord('Z'):
          num -= 26
        elif num < ord('A'):
          num += 26

      elif cipher[cipher_index].islower():
        if num > ord('z'):
          num -= 26
        elif num < ord('a'):
          num += 26

      deciphered_string.append(chr(num))
    else:
      deciphered_string.append(cipher[cipher_index])

  return str("".join(deciphered_string))


def findPossibleKeys(ciphertext):

  for word in words:
    word = word.strip()

    # make sure word is not blank
    if word:

      # decode cipher text using a key from wordlist
      decryptedText = v_decipher(ciphertext, word)

      # if -v is set, print out every decode attempt
      if vverbose:
        print("[DEBUG] trying key '%s':" % str(word))
        print("[DEBUG] " + decryptedText)

      # Check if the cipher was successfully decoded
      if knownstring:
        if knownstring in decryptedText:
          print("Found potential key: '%s'" % word)
          print(decryptedText + '\n')
      else:
        # try detecting english in output
        if vverbose: print('[DEBUG] Attempting to determine success by detecting language')
        try:
          langscores = langdetect.detect_langs(decryptedText)
        except:
          print("[Error] Could not detect language.")
          raise
          sys.exit()
        for languageScore in langscores:
          if language in str(languageScore):
            score = float(str(languageScore).split(':')[1])
            if verbose: print('[DEBUG] key "%s" language score: %s' % (str(word), str(score)))
            if score > matchThreshold:
              print("Found potential key: '%s'" % str(word))
              print("Language match score: %s" % score)
              print(decryptedText + '\n')


def main():

  print("Searching %s keys for potential matches..." % len(words))
  print("Press 'ctrl+C' to exit.\n")

  try:
    findPossibleKeys(ciphertext)
  except KeyboardInterrupt:
    print("\nKeyboard interrupt. Stopping...")
    sys.exit()
  except:
    raise

if __name__ == '__main__':
  main()
