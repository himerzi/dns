#!/usr/bin/python

from copy import copy
from optparse import OptionParser, OptionValueError
import pprint
from random import seed, randint
import struct
from socket import *
from sys import exit
from time import time, sleep
from string import join
import signal, os, random

from gz01.collections_backport import OrderedDict
from gz01.dnslib.RR import *
from gz01.dnslib.Header import Header
from gz01.dnslib.QE import QE
from gz01.inetlib.types import *
from gz01.util import *

#overrode maxint, as my laptop had a maxint that was too large for one of the library functions...
MAXINT = 2147483647
# timeout in seconds to wait for reply
TIMEOUT = 5

# domain name and internet address of a root name server
ROOTNS_DN = "f.root-servers.net."   
ROOTNS_IN_ADDR = "192.5.5.241"
  
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

def custom_rr_cmp(inst, other):
    """
    so that RR's  natively support equality checking
    """
    if inst._type == other._type and inst._dn == other._dn:
        return 0
    return -1
RR.__cmp__ = custom_rr_cmp


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
logger.log(DEBUG2, "NSCache INIT = \n{0}".format(nscache))
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

    
def get_best_ns(ns_cache, qname):
  """
    expects QNAME to be a DomainName - we should throw an error if it isnt.
    returns an ordered dict of the best servers to ask, (based on whats
    in ns_cache) about qname. Has logging to self-document what its doing.
    Also takes into account aliased names we have in the cnamecache
    note use of iterator implemented in DomainNameIter at start of file
  """
  #sname is the name we are searchiing for in our list of ns's
  for super_domain in qname:
      if super_domain in ns_cache:
          logger.log(DEBUG2, "Best matching RR's for {0} are for parent domain \"{1}\"\n the nameserves in cache for that zone are as follows:\n".format(qname, super_domain))
          for key in ns_cache[super_domain].iterkeys():
            logger.log(DEBUG2, "{0}\n".format(key))
          logger.log(DEBUG2, "This will probably get added to SLIST")
          return ns_cache[super_domain]
  else:
    #loop fell through without finding any match
    raise Exception("Bad state, root name wasn't matched, but it should have been!")
    
def construct_response(id, question, answers, authority, additional, RCODE=Header.RCODE_NOERR):
    """
    Packs everything down into dns payload format
    """
    ancount = len(answers)
    nscount = len(authority)
    arcount = len(additional)
    header = Header(id, Header.OPCODE_QUERY, RCODE, qdcount=1, ancount=ancount,
                    nscount=nscount, arcount=arcount, qr=True, aa=False, tc=False, rd=True, ra=True)
    packed_secs = ""
    for sec in [answers, authority, additional]:
        packed_secs += reduce(lambda x, y: x + y.pack(), sec, "")
    return "{0}{1}{2}".format(header.pack(),question.pack(), packed_secs)

def construct_A_query(domain_name):
    """
    Constructs a query for an A record for a given domain name
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

    return ("{0}{1}".format(header.pack(),question.pack()), question)
    
def print_dns_payload(data):
  """
    Used for debugging
  """
  logger.log(DEBUG1, "payload (length:{0} bytes) received is:\n{1}\n".format(len(data), hexdump(data)))
  logger.log(DEBUG1, "Header received  is:\n{0}\n".format(Header.fromData(data)))
  header_len                = len(Header.fromData(data))
  question                  = QE.fromData(data, header_len)
  logger.log(DEBUG1, "Question received  is:\n{0}\n".format(question))

def set_authoritative(subdom, ns_dn):
    """
    subdomain is the domain that NS_DN is an authority for, NS_DN is set as Auth=True in the cache for that domain
    returns a RR representing that NS
    """
    for super_domain in subdom:
        if super_domain in nscache:
            logger.log(DEBUG2,  "setting {0} as auth for parent domain {1} of {2}".format(ns_dn, super_domain, subdom))
            nscache[super_domain][ns_dn]._authoritative = True            
            now = int(time())
            ttl = nscache[super_domain][ns_dn]._expiration - now
            #dn, ttl, nsdn
            #build a resource record representive this authority
            rr_ns = RR_NS(DomainName(super_domain), ttl, ns_dn)
            rr_ns.pack()
            return rr_ns
def construct_ns_rr_from_cache(dn):
    """
    returns any authortitative ns we have in cache for that dn. Wasn't necesarily used in this query.
    Is simply a valid cache entry we have for an Authority for the given dn
    """
    now = int(time())
    for super_domain in dn:
       # print "super: {0} , base {1}".format(super_domain, dn)
        if super_domain in nscache:
            #print "super: {0} , base {1}".format(super_domain, dn)
            for ns in nscache[super_domain]:
                if nscache[super_domain][ns]._authoritative is  True:
                    ttl = nscache[super_domain][ns]._expiration - now
                    rr_ns = RR_NS(DomainName(super_domain), ttl, ns)
                    print "NS: {0}".format(rr_ns)
                    return rr_ns
    return None
    
def construct_a_rr_from_cache(dn):
    """
    returns an A RR for domain name dn, or closest resource record for closest domain name (hence for loop)
    """
    for super_domain in dn:
      if super_domain in acache:
        ce = acache[super_domain]
        ip = ce._dict.keys()[0].toNetwork()
        now = int(time())
        ttl = ce._dict.values()[0]._expiration - now
        rr_a = RR_A(DomainName(super_domain), ttl, ip)
        return RR_A(DomainName(super_domain), ttl, ip)
    return None
  
def parse_rrs(payload, offset, quantity):
  """
    constructs RR objects from byte data
  """
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
  expects a byterepresentation of a RR in dns payload format, and returns the corresponding python class
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
  """
    for parsing responses the program receives from nameservers
  """
  header                    = Header.fromData(payload)
  byte_ptr = len(header)
  config = OrderedDict(zip(["question" , "answer", "authority", "additional"], ["_qdcount", "_ancount", "_nscount", "_arcount"]))
  parsed = {"header" : header}
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
  return parsed

def insert_in_ccache(rr, authoritative=False):
    now = int(time())
    dn = rr._dn
    cnamecache[rr._dn] = CnameCacheEntry(rr._cname, authoritative=authoritative, expiration=rr._ttl+now)

def insert_in_acache(rr, authoritative=False):
  now =  int(time())
  #if rr._dn is already in acache, we should somehow choose which value to keep....
  if isinstance(rr, RR_AAAA):
    return
  acache[rr._dn] = ACacheEntry({InetAddr.fromNetwork(rr._addr) : CacheEntry(expiration=rr._ttl+now, authoritative=authoritative)})
  
def insert_in_nscache(rr,  authoritative = False):
  global nscache
  now   = int(time())
  dn    = rr._dn
  nsdn  = rr._nsdn
  ce    = CacheEntry(expiration=now+rr._ttl, authoritative=authoritative)
  if dn in nscache:
    if nsdn in nscache[dn]:
        if nscache[dn][nsdn]._authoritative is True:
            ce._authoritative = True
            
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
    
def get_expired_cnamecache():
  """
  goes through cnamecache and collects all the keys for expired entries
  """
  now = int(time())
  keys_to_del = []
  for key, ce in cnamecache.iteritems():
      if ce._expiration - now <= 0:
        keys_to_del.append(key)
  return (keys_to_del, cnamecache)
  
def get_expired_nscache():
  """"
  Returns keys for expired records in nscache
  """
  now = int(time())
  keys_to_del = []
  for key, odict in nscache.iteritems():
      for dn, ce in odict.iteritems():
          if ce._expiration - now <= 0:
              keys_to_del.append((key, dn))
  return (keys_to_del, nscache)
  
def get_expired_acache():
    now = int(time())
    keys_to_del = []
    for entry, value in acache.iteritems():
        if value._dict.values()[0]._expiration - now <= 0:
            print "found exp a"
            keys_to_del.append(entry)
    return (keys_to_del, acache)

def update_caches():
    """
    Goes through all the caches, and removes expired records
    """
    a = get_expired_acache()
    c = get_expired_cnamecache()
    ns = get_expired_nscache()
    for keys, cache  in [a, c]:
        for key in keys:
            print "deleting {0}".format(key)
            del cache[key]
    ns_keys, cache = ns
    for key, dn  in ns_keys:
        print "deleting {0}{1}".format(key, dn)
        del nscache[key][dn]
        
def get_ip_from_acache(key):
    """ for pulling an ip address string out of an acache entry"""
    return str(acache[key]._dict.keys()[0])
  
def construct_authorities_for_answers(answers):
    """
    For every A or CNAME in answers, we should include glue for the Authoritative
    NS's for those answers
    """
    domains = [rr._dn for rr in answers]
    glue = {"authority": [], "additional": []}
    for domain  in domains:
        auth =  construct_ns_rr_from_cache(domain)
        additional = construct_a_rr_from_cache(auth._nsdn)
        if auth:
            glue["authority"].append(auth)
        if additional:
            glue["additional"].append(additional)
    return (glue["authority"], glue["additional"])
    
def pick_from_slist(slist):
    """
    Picks the next nameserver we'll query for information about sname (the name thats currently being searched for)
    """
    #make sure we're not picking the same server every time this function is called, as
    #sometimes it will be called multiple times with the same slist. This avoids the possible pitfall
    #of always sending a request over and over to a server that is down/behaving erronously
    items = slist.items()
    random.shuffle(items)
    slist = OrderedDict(items)
    for server in slist:
        logger.log(DEBUG2, "Picking from slist, checking if we have an A record (probably supplied as glue) in cache for: {0}\n".format(server))
        if server in acache:
            logger.log(DEBUG2, "    We have: {0}@{1}\n".format(server, acache[server]._dict.keys()[0]))
            ipv4 = str(acache[server]._dict.keys()[0]) #this is what a ridiculously obfuscated data type looks like!
            return (server, ipv4)
    else:
        return False
def resolve(iteration_count, qid, original_question, qname, sname, slist, sanswers, sauthorities, sadditional):
    """
    This is the workhorse function that does the resolving
    qname is original domain name were looking for
    sname is current name were resolving
    """
    ##an iteration count is kept to ensure we're not stuck in an infinite loop, and are actually getting closer to the answer    
    iteration_count += 1
    #requirement #2
    if iteration_count > 200:
        raise OutOfTimeException("Called resolve too many times, might be stuck in a loop")
    #if we already know about this domain name, and know its an alias
    # compliant with requirement 4 & 7
    if sname in cnamecache:
         now = int(time())
         new_sname = cnamecache[sname]._cname
         cname_record = RR_CNAME(sname, cnamecache[sname]._expiration - now, new_sname)
         sanswers.append(cname_record)
         return resolve(iteration_count, qid, original_question, qname, new_sname, get_best_ns(nscache, new_sname), sanswers, sauthorities, sadditional)
    #if we  know about the a record for this name, requirement 7
    if sname in acache:
        now = int(time())
        ip = acache[sname]._dict.keys()[0].toNetwork()
        exp = acache[sname]._dict.values()[0]._expiration - now
        answer_a_record = RR_A (sname, exp, ip)
        sanswers.append(answer_a_record)
        #adds records we need to keep track of to comply with requirement 6
        sauthorities, sadditional = construct_authorities_for_answers(sanswers)
        our_response = (qid, original_question, sanswers, sauthorities, sadditional)
        return our_response

    ns_to_query = pick_from_slist(slist)
    if not ns_to_query:
        logger.log(DEBUG1, "exhausted list, and couldnt find anything about these servers in our cache, will have to query from root")
        new_qname = next(slist.iterkeys())
        #we now have to resolve one of these servers as if it were a normal domain query,
        #save the answer, and use it to continue our original query, we should iterate through each server
        # check the return value for a succesful resolution, and carry on.
        #shouldnt need qid nor original question (still refers to old question)
        #essentially calling resolve in this case will cause side-effects that update the cache with
        #the entries we need
        resolve(iteration_count, qid , original_question, new_qname, new_qname, get_best_ns(nscache, new_qname), [], [], [])
        #continue search as before
        return resolve(iteration_count, qid, original_question, qname, sname, get_best_ns(nscache, sname), sanswers, sauthorities, sadditional)
    ##
    (name_server, ipv4) = ns_to_query
    #logger.log(DEBUG2, "CCache is:\n{0}\n".format(pp.pformat(cnamecache)))
    address                   = (ipv4,53)
    payload, question         = construct_A_query(sname)
    
    logger.log(DEBUG1, "sending question for A record for  {0}  to {1} @{2}:\n{3}\n".format(question._dn, name_server, address, hexdump(payload)))

    #requirement #8
    cs.sendto(payload, address)
    try:
         (cs_data, cs_address,)    = cs.recvfrom(512)
    except timeout:
        #try a different server, requirement 8
        logger.info("Timed out, trying someone else")
        return resolve(iteration_count, qid, original_question, qname, sname, get_best_ns(nscache, sname), sanswers, sauthorities, sadditional)    
            
    response = parse_response_payload(cs_data)
    #if is authority, set its records  in cache as authoritative
    #also adds records we need to keep track of to comply with requirement 5
    if response["header"]._aa is 1:
        #print "response {0} from {1} ".format(response, name_server)
        logger.log(DEBUG1, "{0}".format( name_server))
        ns_ns_rr = set_authoritative(sname, name_server)
        ns_a_rr = construct_a_rr_from_cache(name_server)
        if ns_ns_rr not in sauthorities:
            sauthorities.append(ns_ns_rr)
        if ns_a_rr not in sadditional:
            sadditional.append(ns_a_rr)
                
    load_response_into_cache(response)
    logger.log(DEBUG2, "Answer received from {0} server is:\n {1}".format(name_server, pp.pformat(response)))
    logger.log(DEBUG1, "*"*50)
    answer_sec = response["answer"]
    ##if there is an answer in the response, either its a cname or an a record
    #if its an A, we're done, if its a CNAME we're not
    if len(answer_sec) > 0:
        sanswers.append(response["answer"][0])
        logger.log(DEBUG2, "Sanswers is {0}".format(pp.pformat(sanswers)))
        ##part of fulfilling requirement 4
        if answer_sec[0]._type is RR.TYPE_CNAME:
            sname  =  answer_sec[0]._cname
            return resolve(iteration_count, qid, original_question, qname, sname,  get_best_ns(nscache, sname), sanswers, sauthorities, sadditional)
        our_response = (qid, original_question, sanswers, sauthorities, sadditional)
        logger.log(DEBUG1, "&#"*50+"\n"*3+"Response:\n{0}".format(our_response))
        return our_response       
    return resolve(iteration_count, qid, original_question, qname, sname, get_best_ns(nscache, sname), sanswers, sauthorities, sadditional)
 
class OutOfTimeException(Exception):
  def __init__(self, value):
    self.value = value
      
  def __str__(self):
    return repr(self.value)
  
def exc(qid, qname, question):
    """
    Handles calling the resolve function
    """    

    def handler(signum, frame):
        print 'Signal handler called with signal', signum
        raise OutOfTimeException("Query couldn't be processed in under 1 minute!")
    try:
        # Set the signal handler and a 60 second alarm
        # as per requirement 2
        signal.signal(signal.SIGALRM, handler)
        signal.alarm(60)
        ##clean out expired records before we handle this query
        update_caches() 
        response  = construct_response(*resolve(0, qid, question, qname, qname, get_best_ns(nscache, qname), [], [], []))
        signal.alarm(0)   
    except (OutOfTimeException) as e:
        # Server Failure
        logger.error(e)
        signal.alarm(0)
        response = construct_response(qid, question, [], [], [], RCODE=Header.RCODE_SRVFAIL)
    return response 
# This is a simple, single-threaded server that takes successive
# connections with each iteration of the following loop:
while 1:
  logger.log(DEBUG1, "\n"*40)
  logger.log(DEBUG1, "="*400)
  
  (data, address,)         = ss.recvfrom(512) # DNS limits UDP msgs to 512 bytes
  if not data:
    log.error("client provided no data")
    continue
  header = Header.fromData(data)
  qid = header._id
  header_len                = len(header)
  question = QE.fromData(data, header_len)
  qname                     = DomainName.fromData(data, header_len)
  response = exc(qid, qname, question)
  ss.sendto(response, address)
  
