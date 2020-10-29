#!/bin/bash

socat tcp-l:9999,fork exec:/home/pwn/pwn,reuseaddr
