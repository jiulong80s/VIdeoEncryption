ENCRYPTION:
clear; ./encryption.exe -i /home/fabio/workspace2/DemoTS/file34-10MB.mpg -o /home/fabio/workspace2/DemoTS/enc.mpg -k 000202030407060708090A0B0C0D0E0F -v 000102030405060708090A0B0C0D0E0F -e 1


DECRYPTION:
clear; ./encryption.exe -i /home/fabio/workspace2/DemoTS/enc.mpg -o /home/fabio/workspace2/DemoTS/clear.enc.mpg -k 000202030407060708090A0B0C0D0E0F -v 000102030405060708090A0B0C0D0E0F -e 0

