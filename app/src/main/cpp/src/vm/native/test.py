a=0x98293212
#a=0x5
b=a&3
print"b:%x"%b
while(b):
    print "a:%x"%a
    a=a+1
    b=a&3