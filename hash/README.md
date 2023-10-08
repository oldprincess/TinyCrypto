# TinyCrypto -- Hash

## GHash

> Dworkin M. Recommendation for block cipher modes of operation: Galois/Counter Mode (GCM) and GMAC[R]. National Institute of Standards and Technology, 2007.
> https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf

* ghash common

* ghash lut

> McGrew D, Viega J. The Galois/counter mode of operation (GCM)[J]. submission to NIST Modes of Operation Process, 2004, 20: 0278-0070.
> https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf

* ghash pclmul

> Intel Carry-Less Multiplication Instruction and its Usage for Computing the GCM Mode.
> https://www.intel.com/content/dam/develop/external/us/en/documents/clmul-wp-rev-2-02-2014-04-20.pdf

```
-mssse3 -mpclmul
```