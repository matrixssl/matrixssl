Wrapper API
===========

This is example wrapper for OS API.

Currently only the memory allocation API is wrapped.
This example shows how to wrap APIs in case the operating system does
not provide `malloc()` functions.

In addition, this lib can be used to check where `malloc()` or `free()` has
been inadvertebly used instead of Malloc() or Free().

