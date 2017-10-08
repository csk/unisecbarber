# -*- coding: utf-8 -*-

'''
Copyright (c) 2017, Conrad Stein K
All rights reserved.
'''

import os
def term_width_line_msg(msg='',ch="#"):
	rows, columns = os.popen('stty size', 'r').read().split()
	mul = int(columns) - len(msg) - 2
	bar=ch*int(mul/2)
	return "%s %s %s" % (bar, msg, bar)
