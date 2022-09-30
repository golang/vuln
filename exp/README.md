### Experimental Packages

This directory holds experimental packages for x/vuln.

It was originally created in order to provide exported APIs for experimental IDE features, through integration with gopls. These APIs would otherwise be kept under internal/, since they are likely to be unstable.

Warning: Packages here are experimental and unreliable. Some may one day be promoted to an exported package under this repository, or they may be modified arbitrarily or even disappear altogether.

In short, there is no compatibility promise for code in this directory. (There is currently no compatibility promise for the entire x/vuln repository, since it is untagged, but other packages can be expected to be relatively stable. Packages under this directory are likely to change without warning.)

Caveat emptor.
