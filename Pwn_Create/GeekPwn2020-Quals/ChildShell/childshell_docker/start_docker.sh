#!/bin/bash

docker run -it --cap-add SYS_ADMIN -p 23333:9999 geekpwn/childshell /bin/bash
