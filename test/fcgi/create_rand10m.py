#coding:utf8
'''
Create a size of 10M file whth random data
'''
import random
import StringIO
import hashlib

def randdata(size):
	s = StringIO.StringIO()
	for i in xrange(size):
		s.write(chr(random.randrange(0,128)))
	return s.getvalue()


if __name__ == '__main__':
	filename = 'rand10m'
	firstmd5 = '' 
	with open(filename, 'w') as fp:
		data = randdata(2**20)
		md5 = hashlib.md5()
		md5.update(data)
		firstmd5 = md5.hexdigest()
		fp.write(data)
		for i in xrange(9):
			data = randdata(2**20)
			md5.update(data)
			fp.write(data)
		finalmd5 = md5.hexdigest()
	print firstmd5, finalmd5

