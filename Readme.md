# Installation

  virtualenv venv 
  source venv/bin/activate
  pip install -r requirements.txt 

# Usage 


    python imgStore.py -h 

Store object with key testtest

    python imgStore.py -k testtest -c -f chocolatesymbol.png plague-chan.png

Outputs file ~/chocolatesymbol.png.out which contains plague-chan.png. 

You can list an archive like: 


    python imgStore.py -k testtest -t -f chocolatesymbol.png.out 
    plague-chan.png
    plague-chan.png: 278476 bytes

And extract your objects again by: 

    python imgStore.py -k testtest -x -f chocolatesymbol.png.out
    plague-chan.png 
    Unpacking plague-chan.png to plague-chan.png.out
