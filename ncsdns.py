#!/usr/bin/python

from copy import copy
from optparse import OptionParser, OptionValueError
import pprint
from random import seed, randint
import struct
from socket import *
from sys import exit, maxint as MAXINT
from time import time, sleep
from string import join

from gz01.collections_backport import OrderedDict
from gz01.dnslib.RR import *
from gz01.dnslib.Header import Header
from gz01.dnslib.QE import QE
from gz01.inetlib.types import *
from gz01.util import *

# timeout in seconds to wait for reply
TIMEOUT = 5

# domain name and internet address of a root name server
ROOTNS_DN = "f.root-servers.net."   
ROOTNS_IN_ADDR = "192.5.5.241"

#Logging config - not used
#LOG_FORMAT = '%(lineno)d: %(message)s'
#logger.basicConfig(format=LOG_FORMAT)

class ACacheEntry:
  ALPHA = 0.8

  def __init__(self, dict, srtt = None):
    self._srtt = srtt
    self._dict = dict

  def __repr__(self):
    return "<ACE %s, srtt=%s>" % \
      (self._dict, ("*" if self._srtt is None else self._srtt),)

  def update_rtt(self, rtt):
    old_srtt = self._srtt
    self._srtt = rtt if self._srtt is None else \
      (rtt*(1.0 - self.ALPHA) + self._srtt*self.ALPHA)
    logger.debug("update_rtt: rtt %f updates srtt %s --> %s" % \
       (rtt, ("*" if old_srtt is None else old_srtt), self._srtt,))

class CacheEntry:
  def __init__(self, expiration = MAXINT, authoritative = False):
    self._expiration = expiration
    self._authoritative = authoritative

  def __repr__(self):
    now = int(time())
    return "<CE exp=%ds auth=%s>" % \
           (self._expiration - now, self._authoritative,)

class CnameCacheEntry:
  def __init__(self, cname, expiration = MAXINT, authoritative = False):
    self._cname = cname
    self._expiration = expiration
    self._authoritative = authoritative

  def __repr__(self):
    now = int(time())
    return "<CCE cname=%s exp=%ds auth=%s>" % \
           (self._cname, self._expiration - now, self._authoritative,)

class DomainNameIter:
    """ this makes it easy to iterate over a DomainName from its fully qualified
    name to its least qualified, "node" by "node"
     """
    def __init__(self, domain_name_string):
        self.split_dname = str(domain_name_string).split(".")
        #i is our counter for which segment of the domain name were iterating through
        self.i = 0

    def __iter__(self):
        return self

    def next(self):
        if self.i == len(self.split_dname):
            raise StopIteration()
        elif self.i == len(self.split_dname)-1:
            self.i += 1
            return "."
        else:
            domain_name = join(self.split_dname[self.i:len(self.split_dname)], ".")
            self.i += 1
            return domain_name
DomainName.__iter__  = lambda instance: DomainNameIter(str(instance))


# >>> entry point of ncsdns.py <<<

# Seed random number generator with current time of day:
now = int(time())
seed(now)

# Initialize the pretty printer:
pp = pprint.PrettyPrinter(indent=3)

# Initialize the name server cache data structure; 
# [domain name --> [nsdn --> CacheEntry]]:
nscache = dict([(DomainName("."), 
            OrderedDict([(DomainName(ROOTNS_DN), 
                   CacheEntry(expiration=MAXINT, authoritative=True))]))])
logger.log(DEBUG2, "NSCache INIT = \n{}".format(nscache))
# Initialize the address cache data structure;
# [domain name --> [in_addr --> CacheEntry]]:
acache = dict([(DomainName(ROOTNS_DN),
           ACacheEntry(dict([(InetAddr(ROOTNS_IN_ADDR),
                       CacheEntry(expiration=MAXINT,
                       authoritative=True))])))]) 

# Initialize the cname cache data structure;
# [domain name --> CnameCacheEntry]
cnamecache = dict([])

# Parse the command line and assign us an ephemeral port to listen on:
def check_port(option, opt_str, value, parser):
  if value < 32768 or value > 61000:
    raise OptionValueError("need 32768 <= port <= 61000")
  parser.values.port = value

parser = OptionParser()
parser.add_option("-p", "--port", dest="port", type="int", action="callback",
                  callback=check_port, metavar="PORTNO", default=0,
                  help="UDP port to listen on (default: use an unused ephemeral port)")
(options, args) = parser.parse_args()

# Create a server socket to accept incoming connections from DNS
# client resolvers (stub resolvers):
ss = socket(AF_INET, SOCK_DGRAM)
ss.bind(("127.0.0.1", options.port))
serveripaddr, serverport = ss.getsockname()

# NOTE: In order to pass the test suite, the following must be the
# first line that your dns server prints and flushes within one
# second, to sys.stdout:
print "%s: listening on port %d" % (sys.argv[0], serverport)
sys.stdout.flush()

# Create a client socket on which to send requests to other DNS
# servers:
setdefaulttimeout(TIMEOUT)
cs = socket(AF_INET, SOCK_DGRAM)

  #dummy data
#data                      = "\x86\x9f\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04sipb\x03mit\x03edu\x00\x00\x01\x00\x01"
#resp_data                 = "\xb8\xfe\x80\x00\x00\x01\x00\x00\x00\x06\x00\x07\x05qsipb\x03mit\x03edu\x00\x00\x01\x00\x01\xc0\x16\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x13\x01f\x0bedu-servers\x03net\x00\xc0\x16\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01g\xc0-\xc0\x16\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01c\xc0-\xc0\x16\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01a\xc0-\xc0\x16\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01l\xc0-\xc0\x16\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01d\xc0-\xc0j\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0\x05\x06\x1e\xc0Z\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0\x1a\\\x1e\xc0\x8a\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0\x1fP\x1e\xc0+\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0#3\x1e\xc0J\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0*]\x1e\xc0J\x00\x1c\x00\x01\x00\x02\xa3\x00\x00\x10 \x01\x05\x03\xcc,\x00\x00\x00\x00\x00\x00\x00\x02\x006\xc0z\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0)\xa2\x1e"

def resolve_cname_in_cache(sname):
  """
  Finds what cname this sname ultimately resolves to in cnamecache
  sname is a DomainName
  """
  if sname not in cnamecache:
    #raise Exception("trying to resolve a cname in cache, that isn't in the cache!")
    return False
  if cnamecache[sname]._cname in cnamecache:
    return resolve_cname_in_cache(cnamecache[sname]._cname)
  return OrderedDict([(cnamecache[sname]._cname, cnamecache[sname])])
    
def get_best_ns(ns_cache, qname):
  """
    expects QNAME to be a DomainName - we should throw an error if it isnt.
    returns an ordered dict of the best servers to ask, (based on whats
    in ns_cache) about qname. Has logging to self-document what its doing.
    Also takes into account aliased names we have in the cnamecache
  """
  #sname is the name we are searchiing for in our list of ns's
  #logger.log(DEBUG2, "NSCache (out) is:\n{}\n".format(pp.pformat(nscache)))
  #logger.log(DEBUG2, "NSCache (in)  is:\n{}\n".format(pp.pformat(ns_cache)))
  for super_domain in qname:
      if super_domain in ns_cache:
          logger.log(DEBUG2, "Best matching RR's for {} are for parent domain \"{}\"\n the nameserves in cache for that zone are as follows:\n".format(qname, super_domain))
          for key in ns_cache[super_domain].iterkeys():
            logger.log(DEBUG2, "{}\n".format(key))
          logger.log(DEBUG2, "This will probably get added to SLIST")
          return ns_cache[super_domain]
  else:
    #loop fell through without finding any match
    raise Exception("Bad state, root name wasn't matched, but it should have been!")    
def construct_response(id, question, answers):
    ancount = len(answers)
    header = Header(id, Header.OPCODE_QUERY, Header.RCODE_NOERR, qdcount=1, ancount=ancount,
                    nscount=0, arcount=0, qr=True, aa=False, tc=False, rd=True, ra=True)
    packed_answers = reduce(lambda x, y: x + y.pack(), answers, "")
    return "{}{}{}".format(header.pack(),question.pack(), packed_answers)
def construct_A_query(domain_name):
    """
    domain name is the domain name we're querying about
    """
    #generate a 16 bit random number - Header class ensures this is packed correctly
    h_id                    = randint(0, 65535)
    header                  = Header(h_id, Header.OPCODE_QUERY, Header.RCODE_NOERR,
                    qdcount = 1, ancount=0, nscount=0, arcount=0, qr=False,
                    aa      = False, tc=False, rd=False, ra=False)
    if not isinstance(domain_name, DomainName):
        raise Exception("construct_A_query didnt receive a domain name of type DomainName")
    
    question                = QE(type=QE.TYPE_A, dn=domain_name)

    return ("{}{}".format(header.pack(),question.pack()), question)
    
def print_dns_payload(data):
  logger.log(DEBUG1, "payload (length:{} bytes) received is:\n{}\n".format(len(data), hexdump(data)))
  logger.log(DEBUG1, "Header received  is:\n{}\n".format(Header.fromData(data)))
  header_len                = len(Header.fromData(data))
  question                  = QE.fromData(data, header_len)
  logger.log(DEBUG1, "Question received  is:\n{}\n".format(question))
  #logger.log(DEBUG2, "raw from {} type {}:\n{}".format(address,type(data), repr(data)))

def parse_rrs(payload, offset, quantity):
  rrs = []
  for i in range(quantity):
    subtype = get_record_type(payload, offset)
   # print "subtype " + subtype
    rr, length = subtype.fromData(payload, offset)
    rrs.append(rr)
    offset += length
    
  return rrs, offset

def get_record_type(rr, offset=0):
  """
  expects a raw representation of a RR, and returns the corresponding python class
  _type -- The DNS type of this resource record; one of { RR.TYPE_A
  (DNS A record), RR.TYPE_NS (DNS NS record), RR.TYPE_CNAME (DNS CNAME
  record), RR.TYPE_SOA (DNS start-of-authority record), RR.TYPE_PTR
  (DNS PTR record), RR.TYPE_MX (DNS mail exchange record),
  RR.TYPE_AAAA (DNS IPv6 address record).
  """
  (generic_type, _) = RR.fromData(rr,offset)
  return {
        RR.TYPE_A : RR_A,
        RR.TYPE_AAAA : RR_AAAA,
        RR.TYPE_NS : RR_NS,
        RR.TYPE_CNAME : RR_CNAME
        }[generic_type._type]
      
def parse_response_payload(payload):
  header                    = Header.fromData(payload)
  byte_ptr = len(header)
  config = OrderedDict(zip(["question" , "answer", "authority", "additional"], ["_qdcount", "_ancount", "_nscount", "_arcount"]))
  parsed = {}
  for key, val in config.items():
    #the question section isn't parsed as a RR, needs special treatment
    if key is "question":
      #assumes only ever receive one question entry
      if getattr(header, val) > 1:
        raise Exception("Uh oh!")
      question = QE.fromData(payload, byte_ptr)
      parsed[key] = [question,]
      byte_ptr += len(question)
        
    else:
      num_entries = getattr(header, val)
      rrs, byte_ptr = ([], byte_ptr) if num_entries is 0 else parse_rrs(payload,
                                                                        byte_ptr,
                                                                        num_entries)    
      parsed[key] = rrs
  #logger.log(DEBUG2, "parsed:\n{}\n".format(pp.pformat(parsed)))
  return parsed
def insert_in_ccache(rr, authoritative=False, expiration=MAXINT):
    dn = rr._dn
    cnamecache[rr._dn] = CnameCacheEntry(rr._cname, authoritative=authoritative, expiration=expiration)

def insert_in_acache(rr, authoritative=False):
  global acache
  #if rr._dn is already in acache, we should somehow choose which value to keep....
  if isinstance(rr, RR_AAAA):
    return
  acache[rr._dn] = ACacheEntry({InetAddr.fromNetwork(rr._addr) : CacheEntry(expiration=rr._ttl, authoritative=authoritative)})
  #return acache
def insert_in_nscache(rr,  authoritative=False):
  global nscache
  
  dn = rr._dn
  nsdn = rr._nsdn
  ce =  CacheEntry(expiration=rr._ttl, authoritative=authoritative)
  if dn in nscache:
   
    nscache[dn][nsdn] = ce
  else:
   
    nscache[dn] = OrderedDict([(nsdn, ce)])
def load_records_into_cache(rrs):
    for rr in rrs:
      rrt = rr._type  
      if rrt is RR.TYPE_A:
        insert_in_acache(rr)
      elif rrt is RR.TYPE_CNAME:
        insert_in_ccache(rr)
      elif rrt is RR.TYPE_NS:
        insert_in_nscache(rr)    
          
def load_response_into_cache(response):
  for key in ["answer", "authority", "additional"]:
    load_records_into_cache(response[key])

def get_ip_from_acache(key):
    return str(acache[key]._dict.keys()[0])
#def construct_cname_rr():
def resolve(qid, original_question, qname, sname, slist, sanswers=[]):
    """
    qname is original domain name were looking for
    sname is current name were resolving
    """
  #for i in range(2):
    #global acache, nscache
    #logger.log(DEBUG2, "Acache is:\n{}\n".format(pp.pformat(acache)))
    #logger.log(DEBUG2, "NSCache is:\n{}\n".format(pp.pformat(nscache)))
          #check if its an alias we know of
    if sname in cnamecache:
         #print resolve_cname_in_cache(sname)
         cname_record = RR_CNAME(sname, 1, cnamecache[sname]._cname)
         sanswers.append(cname_record)
         new_sname = cnamecache[sname]._cname
         return resolve(qid, original_question, qname, new_sname, get_best_ns(nscache, new_sname), sanswers)
    if sname in acache:
        ip = acache[sname]._dict.keys()[0].toNetwork()
        answer_a_record = RR_A (sname, 1, ip)
        sanswers.append(answer_a_record)
        #our_response = construct_response(qid, original_question, sanswers)
        our_response = (qid, original_question, sanswers)
        logger.log(DEBUG1, "wang"*50+"\n"*3+"Response:\n{}".format(our_response))
        return our_response

    for server in slist:
        #print "slist {}".format(slist)
        firstup = server
        logger.log(DEBUG2, "Picking from slist, checking if we have an A record (probably supplied as glue) in cache for: {}\n".format(server))
        if server in acache:
 
            logger.log(DEBUG2, "    We have: {}@{}\n".format(server, acache[server]._dict.keys()[0]))
            ipv4 = str(acache[server]._dict.keys()[0]) ##this is what a ridiculously obfuscated data type looks like!
            break
    else:
        #exhausted list, and couldnt find anything about these servers in our cache which shouldnt be the case
        #beacuse only servers in our cache get added to slist... and everything should fall back to the root server
        logger.log(DEBUG1, "exhausted list, and couldnt find anything about these servers in our cache")
        new_qname = next(slist.iterkeys())
        #print "server {}".format(slist)
        #print "not here"
        #we now have to resolve one of these servers as if it were a normal domain query,
        #save the answer, and use it to continue our original query, we should iterate through each server
        # check the return value for a succesful resolution, and carry on.
        #shouldnt need qid nor original question (still refers to old question)
        (_, original_question, _sanswers) = resolve(qid , original_question, new_qname, new_qname, get_best_ns(nscache, new_qname), [])
        print "we found {} answers {}".format(new_qname, _sanswers)
        load_records_into_cache(_sanswers)
        #continue search as before
        return resolve(qid, original_question, qname, sname, get_best_ns(nscache, sname), sanswers)
               #if qname actually is an alias for sname, and we already have an 
            # A record for sname in cache, then we're all done!
            #first check if qname is an alias, then see what it resolves to
    
    #logger.log(DEBUG2, "CCache is:\n{}\n".format(pp.pformat(cnamecache)))
    address                   = (ipv4,53)
    payload, question                   = construct_A_query(sname)
    
    logger.log(DEBUG1, "sending question for A record  {}  to {} @{}:\n{}\n".format(question._dn, firstup, address, hexdump(payload)))
    cs.sendto(payload, address)
    (cs_data, cs_address,)    = cs.recvfrom(512)
    
    
    #print_dns_payload(cs_data)
    
    #would need to check if this response is actually getting us closer....
    
    response = parse_response_payload(cs_data)
    load_response_into_cache(response)
    logger.log(DEBUG2, "Answer received from {} server is:\n {}".format(firstup, pp.pformat(response)))
    logger.log(DEBUG1, "*"*50)
    answer_sec = response["answer"]
    if len(answer_sec) > 0:
        sanswers.append(response["answer"][0])
        logger.log(DEBUG2, "Sanswers is {}".format(pp.pformat(sanswers)))
        if answer_sec[0]._type is RR.TYPE_CNAME:
            sname  =  answer_sec[0]._cname
            return resolve(qid, original_question, qname, sname,  get_best_ns(nscache, sname), sanswers=sanswers)
        #our_response = construct_response(qid, original_question, sanswers)
        our_response = (qid, original_question, sanswers)
        logger.log(DEBUG1, "&#"*50+"\n"*3+"Response:\n{}".format(our_response))
        return our_response
   
    
    #
    #could go into infinite loop if our response getting loaded into cache doesnt get us any closer to qname
    return resolve(qid, original_question, qname, sname, get_best_ns(nscache, sname), sanswers=sanswers)
   # slist = 
   # logger.log(DEBUG2, "new slist:\n{}".format(slist))
#    logger.log(DEBUG2, "new ns:\n{}\nNewA:\n{}".format(new_ns, new_a))
def exc(qid, qname, question):
     return construct_response(*resolve(qid, question, qname, qname, get_best_ns(nscache, qname), sanswers=[]))
# This is a simple, single-threaded server that takes successive
# connections with each iteration of the following loop:
while 1:
  logger.log(DEBUG1, "\n"*40)
  logger.log(DEBUG1, "="*400)
  
  (data, address,)         = ss.recvfrom(512) # DNS limits UDP msgs to 512 bytes
  print "data"
  if not data:
    log.error("client provided no data")
    continue
  #print_dns_payload(data)
  header = Header.fromData(data)

  #print "id: " + repr(header._id)
  qid = header._id
  header_len                = len(header)
  question = QE.fromData(data, header_len)
  qname                     = DomainName.fromData(data, header_len)
  response = exc(qid, qname, question)
  #logger.info( "&#"*50+"\n"*3+"Response:\n{}".format(response))
#  ss.sendto(reply, acache[firstup])
  ss.sendto(response, address)
  
 # break
