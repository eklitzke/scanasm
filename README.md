This is a project to analyze x86 files.

To build this project you will need autotools (i.e. autoconf, automake) and
header files for [Capstone](http://www.capstone-engine.org/). To build the code
from a fresh git checkout:

```
$ ./autogen.sh
$ ./configure
$ make
```

Afterwards there will be an executable at `./src/scanasm`. If you wish to
install this permanently, you can use `make install` the usual way.

This project is free software licensed under the GPLv3+.
