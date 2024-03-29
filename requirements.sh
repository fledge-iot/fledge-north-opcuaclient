#!/usr/bin/env bash

##---------------------------------------------------------------------------
## Copyright (c) 2022 Dianomic Systems Inc.
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##     http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
##---------------------------------------------------------------------------

##
## Author: Mohi SIngh Tomar
##


pygte37=$(python3 -c 'import sys; print("Y") if sys.version_info.major >= 3 and sys.version_info.minor >= 7 else print("N")')

if [ ${pygte37} == "N" ]
then
    echo "Requires platform with Python >= 3.7"
    exit 1
  
fi

python3 -m pip install -Ir python/requirements-opcuaclient.txt