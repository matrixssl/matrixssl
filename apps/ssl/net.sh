#!/bin/sh
set -e
if [ -e apps/ssl ];then cd apps/ssl;fi

set -x
./matrixnet --help
./matrixnet --get http://www.insidesecure.com/ || echo Failed expectedly.
(./matrixnet --get http://essjira.insidesecure.com | fold -w 80 | head -10)
(./matrixnet --get http://localhost/ | fold -w 80 | head -10)

echo "Successful test for (matrix)net."
