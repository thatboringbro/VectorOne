# this method checks the local database for the file hash and returns 
# a boolean value indicating whether the file is present or not

def analyze(file_hash: str) -> bool:
    # placeholder for now, will implement later
    # check the local database for the file hash
    # get the verdict for the file hash
    # return the verdict (this algorithm is simpler because I'm trying to make it
    # lean and efficient)
    pass

def check_virustotal():
    # connect via virustotal API and check the file hash
    # return the verdict
    # I have to understand the sdata shape that VT will return then I can 
    # design this method to parse the data and return the verdict