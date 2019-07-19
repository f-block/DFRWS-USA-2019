# Volatility Plugins

This folder contains the source code of all external plugins used during our research.
The link to the corresponding repositories, according with their commit number, are listed below.

## Modified Plugins

* [Hashtest](https://github.com/f-block/Hashtest/)
   We created a fork of the [original repository](https://github.com/a-white/Hashtest/tree/5bd60455b3a06070bfa454fe55e4b66b25c502d4) with the following modifications:
   **Hashbuild:**
   Fixed bug that prevents the offsets from being put into the hashset

   **Hashtest:**
   Some bug fixes and adjustments to make this plugin compatible with the current version of volatility.
   The bug fixes include:
   * The transition check in check_executable does not test for the valid flag and hence, also treats valid and writable (bit 11 set) pages as in transition.
   * Catching key index exception for unknown files
   * Preventing divison by zero exception while calculating the "Exec percentage"


## Unmodified Plugins

* [hollowfind](https://github.com/monnappa22/HollowFind/tree/58aa3990807154cc8860137754f3bfa92deb644b)
* [threadmap](https://github.com/kslgroup/threadmap/tree/2f31a49ef8dc8e98b20a92a8169d93db9da8bd1e)
* [malfofind and malthfind](https://github.com/volatilityfoundation/community/tree/c70fb62359a80d48763945926a3ae7952dbc9106/DimaPshoul)
* [psinfo](https://github.com/monnappa22/Psinfo/tree/48c60d3153076a315fdeff956e1656565180ad82)
