#!/bin/bash
socat tcp-l:9999,fork exec:"/home/pwn/pwn/parent /home/pwn/pwn/pwn",reuseaddr
