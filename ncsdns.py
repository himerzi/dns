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
  """
  #sname is the name we are searchiing for in our list of ns's
  
  for super_domain in qname:
      if super_domain in ns_cache:
          logger.log(DEBUG2, "Best matching RR's for {} are for parent domain \"{}\":\n".format(qname, super_domain))
          for key in ns_cache[super_domain].iterkeys():
            logger.log(DEBUG2, "{}\n".format(key))
          return ns_cache[super_domain]
  raise Exception("Bad state, root name wasn't matched, but it should have been!")    

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

    return "{}{}".format(header.pack(),question.pack())
    
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
    rr, length = subtype.fromData(payload, offset)
    rrs.append(rr)
    offset += length
  return rrs, offset
def calculate_total_length(rrs):
  """
  expects a list or Resource Records, computes their total length
  """
  return reduce(lambda x, y: x  + len(y), rrs, 0)

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
  print "gen type {}".format(generic_type._type)
  return {
        RR.TYPE_A : RR_A,
        RR.TYPE_AAAA : RR_AAAA,
        RR.TYPE_NS : RR_NS,
        RR.TYPE_CNAME : RR_CNAME
        }[generic_type._type]
      
def parse_response_payload(payload):
  header                    = Header.fromData(payload)
  hlen = len(header)
  byte_ptr = hlen
  config = OrderedDict(zip(["question" , "answer", "authority", "additional"], ["_qdcount", "_ancount", "_nscount", "_arcount"]))
  parsed = {}
  for key, val in config:
    num_entries = header.getattr(val)
    rrs, byte_ptr = ([], byte_ptr) if num_entries is 0 else parse_rrs(payload,
                                                                              byte_ptr,
                                                                              num_entries)
    
    parsed[key] = rrs
    logger.log(DEBUG2, "parsed:\n{}\n".format(parsed))
  #As per requirements, we assume there is only ever one question
  # ***perhaps we should be checking that there is at least a question present...
  
  # parse CNAMES, NS, and A records
  # question_start =  hlen
  # question                  = QE.fromData(data, hlen) 
  # answer_start =  question_start + len(question)
  # answers, answers_endpoint = ([], answer_start) if header._ancount is 0 else parse_rrs(payload,
  #                                                                                       answer_start,
  #                                                                                       header._ancount)
  # authority_start = answer_start + answers_endpoint
  # logger.log(DEBUG2, "Auth start is:{}\nAnswers is {}\nAnswer length is {}\n".format(authority_start,
  #                                                                                    answers,
  #                                                                                    calculate_total_length(answers)))
  # authorities , auth_endpoint = ([], authority_start) if header._nscount is 0 else parse_rrs(payload, authority_start,
  #                                                         header._nscount)
  # logger.log(DEBUG2, "Authorities  is:\n{}\n Auths end is {}\n".format(authorities,
  #                                                                        auth_endpoint))
  
  # additionals, additionals_endpoint = ([], additional_start) if header._arcount is 0 else parse_rrs(payload, auth_endpoint, header._arcount)
  # logger.log(DEBUG2, "Additionals  is:\n{}\n".format(additionals))
  
# This is a simple, single-threaded server that takes successive
# connections with each iteration of the following loop:
while 1:
  #(data, address,)         = ss.recvfrom(512) # DNS limits UDP msgs to 512 bytes
  #dummy data
  data                      = '\xadF\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05qsipb\x03mit\x03edu\x00\x00\x01\x00\x01'
  resp_data                 = "\xb8\xfe\x80\x00\x00\x01\x00\x00\x00\x06\x00\x07\x05qsipb\x03mit\x03edu\x00\x00\x01\x00\x01\xc0\x16\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x13\x01f\x0bedu-servers\x03net\x00\xc0\x16\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01g\xc0-\xc0\x16\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01c\xc0-\xc0\x16\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01a\xc0-\xc0\x16\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01l\xc0-\xc0\x16\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01d\xc0-\xc0j\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0\x05\x06\x1e\xc0Z\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0\x1a\\\x1e\xc0\x8a\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0\x1fP\x1e\xc0+\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0#3\x1e\xc0J\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0*]\x1e\xc0J\x00\x1c\x00\x01\x00\x02\xa3\x00\x00\x10 \x01\x05\x03\xcc,\x00\x00\x00\x00\x00\x00\x00\x02\x006\xc0z\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0)\xa2\x1e"
  if not data:
    log.error("client provided no data")
    continue
  print_dns_payload(data)
  header_len                = len(Header.fromData(data))
  qname                     = DomainName.fromData(data, header_len)
  
  slist                     = get_best_ns(nscache, qname)

  firstup                 = slist.popitem()
  ipv4                      = str(acache[firstup[0]]._dict.keys()[0]) ##this is what a ridiculously obfuscated data type looks like!
  address                   = (ipv4,53)
  payload                   = construct_A_query(qname)
  logger.log(DEBUG1, "sending:\n{}\n".format(hexdump(payload)))
  #cs.sendto(payload, address)
  #(cs_data, cs_address,)    = cs.recvfrom(512)
  logger.log(DEBUG2, "Answer received from server  is:\n")
  print_dns_payload(resp_data)
  parse_response_payload(resp_data)
#  ss.sendto(reply, acache[firstup])
 # ss.sendto(reply, address)
  logger.log(DEBUG1, "-"*50)
  break
