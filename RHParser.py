import re
import subprocess
import sys


# Return 1 if v2 is smaller, 
# -1 if v1 is smaller,, 
# 0 if equal 
def versionCompare(v1, v2): 

      
    # This will split both the versions by '.' 
    arr1 = v1.split(".")  
    arr2 = v2.split(".")  

    n = len(arr1) 
    m = len(arr2) 
      
    # converts to integer from string 
    arr1 = [int(i) for i in arr1] 
    arr2 = [int(i) for i in arr2] 
   
    # compares which list is bigger and fills  
    # smaller list with zero (for unequal delimeters) 
    if n>m: 
      for i in range(m, n): 
         arr2.append(0) 
    elif m>n: 
      for i in range(n, m): 
         arr1.append(0) 
      
    # returns 1 if version 1 is bigger and -1 if 
    # version 2 is bigger and 0 if equal 
    for i in range(len(arr1)): 
      if arr1[i]>arr2[i]: 
         return 1
      elif arr2[i]>arr1[i]: 
         return -1
    return 0


# returns most critical CVE in retlist
def getbest(retlist):       
    for lobj in retlist:
        if "SEVERITY : Critical" in lobj:
            return lobj.split("\n")[0].strip()+" (Critical)\n"
    for lobj in retlist:
        if "SEVERITY : Important" in lobj:
            return lobj.split("\n")[0].strip()+" (High)\n"
    for lobj in retlist:
        if "SEVERITY : Moderate" in lobj:
            return lobj.split("\n")[0].strip()+" (Moderate)\n"
    for lobj in retlist:
        if "SEVERITY : Low" in lobj:
            return lobj.split("\n")[0].strip()+" (Low)\n"


def task_rhsecapi(product):
    bashCommand = "./rhsecapi.py  --q-package " + product + " --extract-cves -f severity,cvss,upstream_fix,details"
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    return process.communicate()

def clean_out_rhsecapi(output, product, version):
    cves=''
    best=''
    out=output.split('\n\n')[1:]
    retlist=[]
    x=False
    for obj in out:
        lobj=obj.split("\n")
        for line in lobj:
            if "UPSTREAM_FIX" in line:
                tok=line.split(" ")
                x=False
                for t in tok:
                    if product.lower() in t.lower():
                        x=True
                    regexp = re.compile(r'\d+(\.\d+)+')
                    if regexp.search(t) and x:
                        v1=version
                        v2=t.strip()
                        for letter in 'QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm,;:][-_ ':
                            v1=v1.replace(letter,'')
                            v2=v2.replace(letter,'')
                        v1=v1.strip(".")
                        v2=v2.strip(".")
                        a=versionCompare(v1,v2)    
                        if a==0 or a==-1:
                            retlist.append(obj)
                            break
                        else:
                            x=False
    if retlist==[]: retlist.append("No CVEs found for given product.")
    else:
        best=getbest(retlist)
        for lobj in retlist:
            l=lobj.split("\n")
            for line in l:
                if "CVE" in line and "  " not in line :
                    cves+=line.strip()+", "
        

    ret="\033[32;1m"+product+"/"+version+"\033[0m: "+best+cves[:-2]+"\n\n"
    for e in retlist:
        ret+=e+"\n\n"
        
    return ret



def call_rhsecapi(product,version):
    output, error=task_rhsecapi(product)
    output=output.decode()
    if error!=None:
        print("ERROR!")
    output = clean_out_rhsecapi(output, product, version)
    
    print('\033[44;1m   RHsecapi                                                                   \033[0m\n')
    print(output)
    print('\033[44;1m                                                                              \033[0m')
    print('------------------------------------------------------------------------------')
		

if len(sys.argv) != 5:
	print("\nUsage:\n\t-> python3 RHParser.py -p <product> -v <version>\n")
	exit(1)
	
product=''
version=''
if sys.argv[1]=='-p' and sys.argv[3]=='-v':
    product=sys.argv[2]
    version=sys.argv[4]
elif sys.argv[1]=='-v' and sys.argv[3]=='-p':
    product=sys.argv[4]
    version=sys.argv[2]
else:
    print("\nUsage:\n\t-> python3 RHParser.py -p <product> -v <version>\n")
    exit(1)

call_rhsecapi(product,version)
