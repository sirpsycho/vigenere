# Vigenere

This tool was made to aid in deciphering text encoded with the Vigenere cipher.


# Background

A Vigenere cipher is like a normal substitution cipher (caesar / rot13 / etc) with the added complexity of a secret key. This key is repeated over the length of the cipher text to encode each character differently. Vigenere ciphers can be decoded a number of ways, usually requiring some assumed knowledge of what the output is supposed to be. For example, if the encoded cipher text is relatively long (more than 50-100 characters) and you assume the output to consist of english words, you can use letter frequency analysis techniques to decode the text. Additionally, as long as you have some type of idea what the output will look like (either a specific, unique string or simply that the output will be in plain english), you can brute force the key using a dictionary attack.

This script utilizes a dictionary attack method to crack the Vigenere key and decode the cipher text. In order for the script to know that it has successfully decoded the message, define the -k (--known) variable with a unique string that you know will be included in the decoded output. Ideally, this string is long (>4 characters) or else the script may match incorrectly. If this variable is not defined, the script will default to looking for english words as a way of defining success.


# Usage

```
Usage: python CrackVigenere.py -f <encoded file> -w <wordlist>

Examples:
python CrackVigenere.py -f encoded.txt -w wordlist.txt
python CrackVigenere.py -t 'Ifx xivri uycjc dhe xhbnl vjrg ral znow wvu.' -w wordlist.txt -k 'lazy dog.'

Options:
  -h, --help         show this help message and exit
  -f FILE            define a file containing the encoded cipher text
  -t TEXT            define the encoded cipher text as text directly within
                     the command
  -w WORDLIST        define a wordlist to be used in the dictionary attack.
                     This should be a text file with one key per line.
  -k KNOWN           define a known string that will be in the decoded output.
  -l LANGUAGE        If detecting language, define a two-letter language code
                     (default "en" - English)
  -m MATCHTHRESHOLD  If detecting language, use this option to set a custom
                     success threshold between 0 and 1. (default 0.99)
  -v                 show verbose output
  -V                 show more verbose output (show decoded text for each key
                     in wordlist)
```

# Additional Notes and Usage Tips

As a disclaimer, the language detection functionality tends to match pretty loosely, as it stands currently. It uses the python 'langdetect' module, originally based on Google's language detection library, which seems to focus more on detecting whether a particular text is one language rather than the other. Ideally, this script would use a module that is specifically suited for detecting how closely english text matches real english words. Until a better method is implemented here, try narrowing down your results using the -k option (if you know any specific text that should appear in the output) OR try creating a smaller, specifically-customized wordlist.

The wordlist included in this repository is directly based on the commonly-used "rockyou.txt" wordlist. It is a copy of the rockyou wordlist that has been stripped of words with special characters and upper/lower case duplicates - in order to be more well suited for cracking Vigenere ciphers. As mentioned, to obtain better results, try creating your own custom wordlist full of likely keys.


# Additional Resources

This script drew inspiration from the "Hacking the Vigenere Cipher" article on the Invent with Python site. Their code and extensive write-up can be found [here](https://inventwithpython.com/hacking/chapter21.html).

Another excellent resource is the Vigenere Cracking Tool found [here](https://simonsingh.net/The_Black_Chamber/vigenere_cracking_tool.html). This site makes it much easier to perform letter frequency analysis attacks, which can be very useful especially on longer cipher texts that are otherwise difficult to crack.
